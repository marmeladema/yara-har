import "har_entry"
import "hash"

rule favicon
{
	condition:
		har_entry.request.url == "https://www.google.com/favicon.ico" and
		hash.md5(0, filesize) == "f3418a443e7d841097c714d69ec4bcb8"
}
