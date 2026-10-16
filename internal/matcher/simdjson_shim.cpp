//go:build simdjson

// One pass of simdjson On-Demand over a {method,url,headers,data} object, writing the
// normalized request straight into the caller's buffer. Mirrors jxObject exactly:
// numbers as their JSON text, booleans as true/false, null and nested values as empty,
// last duplicate of method/url/data wins, every headers entry is kept in order.
#include "simdjson.h"
#include <cstring>
#include <string>

using namespace simdjson;

struct waap_sj {
	ondemand::parser parser;
	std::string hdr;
	std::string err;
	long long growths = 0, growth_bytes = 0; // C++ heap growth, invisible to Go's statistics
};

static long long fail(waap_sj *h, error_code e, const char *where) {
	h->err = std::string(where) + ": " + error_message(e);
	return -1;
}

// validate reads a value we do not use, so that malformed JSON inside it is still an
// error: On-Demand only checks what it is asked to read, and jx rejects such input.
static error_code validate(ondemand::value v, int depth) {
	if (depth > 1000) return DEPTH_ERROR;
	ondemand::json_type t;
	error_code e = v.type().get(t);
	if (e) return e;
	switch (t) {
	case ondemand::json_type::object: {
		ondemand::object o;
		if ((e = v.get_object().get(o))) return e;
		for (auto f : o) {
			std::string_view k;
			if ((e = f.unescaped_key().get(k))) return e;
			ondemand::value fv;
			if ((e = f.value().get(fv))) return e;
			if ((e = validate(fv, depth + 1))) return e;
		}
		return SUCCESS;
	}
	case ondemand::json_type::array: {
		ondemand::array a;
		if ((e = v.get_array().get(a))) return e;
		for (auto el : a) {
			ondemand::value ev;
			if ((e = el.get(ev))) return e;
			if ((e = validate(ev, depth + 1))) return e;
		}
		return SUCCESS;
	}
	case ondemand::json_type::string: {
		std::string_view sv;
		return v.get_string().get(sv);
	}
	case ondemand::json_type::number: {
		ondemand::number n;
		return v.get_number().get(n);
	}
	case ondemand::json_type::boolean: {
		bool b;
		return v.get_bool().get(b);
	}
	case ondemand::json_type::null: {
		bool isnull;
		e = v.is_null().get(isnull);
		return e ? e : (isnull ? SUCCESS : INCORRECT_TYPE);
	}
	default:
		return INCORRECT_TYPE;
	}
}

static error_code scalar(ondemand::value v, std::string_view *out) {
	ondemand::json_type t;
	error_code e = v.type().get(t);
	if (e) return e;
	switch (t) {
	case ondemand::json_type::string:
		return v.get_string().get(*out);
	case ondemand::json_type::number: {
		ondemand::number n; // validates the number; the text is taken as written
		if ((e = v.get_number().get(n))) return e;
		std::string_view raw = v.raw_json_token();
		while (!raw.empty() && (raw.back() == ' ' || raw.back() == '\t' || raw.back() == '\n' || raw.back() == '\r'))
			raw.remove_suffix(1);
		*out = raw;
		return SUCCESS;
	}
	case ondemand::json_type::boolean: {
		bool b;
		e = v.get_bool().get(b);
		*out = b ? "true" : "false";
		return e;
	}
	case ondemand::json_type::null: {
		bool isnull;
		e = v.is_null().get(isnull);
		*out = std::string_view();
		return e ? e : (isnull ? SUCCESS : INCORRECT_TYPE);
	}
	case ondemand::json_type::object:
	case ondemand::json_type::array: // nested value where a scalar was expected: empty
		*out = std::string_view();
		return validate(v, 0);
	default: // not a JSON value at all
		return INCORRECT_TYPE;
	}
}

extern "C" {

void *waap_sj_new(void) { return new waap_sj(); }
void waap_sj_free(void *h) { delete (waap_sj *)h; }
size_t waap_sj_capacity(void *h) { return ((waap_sj *)h)->parser.capacity(); }
const char *waap_sj_error(void *h) { return ((waap_sj *)h)->err.c_str(); }

const char *waap_sj_backend(void) {
	static std::string s = std::string("simdjson ") + SIMDJSON_VERSION + ", " +
		get_active_implementation()->name() + " (" + get_active_implementation()->description() + ")";
	return s.c_str();
}

// 0: done, *outlen set. > 0: out is too small, the value is the size needed.
// -1: rejected, waap_sj_error explains.
long long waap_sj_normalize(void *hp, const char *msg, size_t len, size_t cap, char *out, size_t outcap, size_t *outlen) {
	waap_sj *h = (waap_sj *)hp;
	size_t pcap0 = h->parser.capacity(), hcap0 = h->hdr.capacity();
	struct track { // counts buffer growth on every way out of this function
		waap_sj *h; size_t pcap0, hcap0;
		~track() {
			if (h->parser.capacity() > pcap0) { h->growths++; h->growth_bytes += h->parser.capacity() - pcap0; }
			if (h->hdr.capacity() > hcap0) { h->growths++; h->growth_bytes += h->hdr.capacity() - hcap0; }
		}
	} tr{h, pcap0, hcap0};
	ondemand::document doc;
	error_code e = h->parser.iterate(padded_string_view(msg, len, cap)).get(doc);
	if (e) return fail(h, e, "iterate");
	ondemand::object obj;
	if ((e = doc.get_object().get(obj))) return fail(h, e, "object");
	std::string_view method, url, body;
	h->hdr.clear();
	for (auto field : obj) {
		std::string_view key;
		if ((e = field.unescaped_key().get(key))) return fail(h, e, "key");
		ondemand::value v;
		if ((e = field.value().get(v))) return fail(h, e, "value");
		if (key == "method") {
			if ((e = scalar(v, &method))) return fail(h, e, "method");
		} else if (key == "url") {
			if ((e = scalar(v, &url))) return fail(h, e, "url");
		} else if (key == "data") {
			if ((e = scalar(v, &body))) return fail(h, e, "data");
		} else if (key == "headers") {
			ondemand::json_type t;
			if ((e = v.type().get(t))) return fail(h, e, "headers");
			if (t == ondemand::json_type::object) {
				ondemand::object ho;
				if ((e = v.get_object().get(ho))) return fail(h, e, "headers");
				for (auto hf : ho) {
					std::string_view name, val;
					if ((e = hf.unescaped_key().get(name))) return fail(h, e, "header name");
					ondemand::value hv;
					if ((e = hf.value().get(hv))) return fail(h, e, "header value");
					if ((e = scalar(hv, &val))) return fail(h, e, "header value");
					h->hdr.append(name).append(": ").append(val).append("\r\n");
				}
			} else if (t == ondemand::json_type::null) {
				bool isnull;
				if ((e = v.is_null().get(isnull))) return fail(h, e, "headers");
			} else {
				h->err = "headers must be an object or null";
				return -1;
			}
		} else if ((e = validate(v, 0))) { // any other key: not used, but must be valid
			return fail(h, e, "value");
		}
	}
	if (!doc.at_end()) {
		h->err = "trailing content after the object";
		return -1;
	}
	size_t need = method.size() + 1 + url.size() + 11 + h->hdr.size() + 2 + body.size();
	if (need > outcap) return (long long)need;
	char *p = out;
	memcpy(p, method.data(), method.size()); p += method.size();
	*p++ = ' ';
	memcpy(p, url.data(), url.size()); p += url.size();
	memcpy(p, " HTTP/1.1\r\n", 11); p += 11;
	memcpy(p, h->hdr.data(), h->hdr.size()); p += h->hdr.size();
	*p++ = '\r'; *p++ = '\n';
	memcpy(p, body.data(), body.size()); p += body.size();
	*outlen = (size_t)(p - out);
	return 0;
}

void waap_sj_growths(void *hp, long long *n, long long *bytes) {
	waap_sj *h = (waap_sj *)hp;
	*n = h->growths; *bytes = h->growth_bytes;
	h->growths = h->growth_bytes = 0;
}

void waap_noop(void) {}

// Benchmark: every message in one call. Returns the total output size, or -1.
long long waap_sj_bench(void *h, const char *base, const size_t *offs, const size_t *lens, size_t n, size_t total, char *out, size_t outcap) {
	long long sum = 0;
	for (size_t i = 0; i < n; i++) {
		size_t outlen = 0;
		long long r = waap_sj_normalize(h, base + offs[i], lens[i], total - offs[i], out, outcap, &outlen);
		if (r != 0) return -1;
		sum += (long long)outlen;
	}
	return sum;
}

} // extern "C"
