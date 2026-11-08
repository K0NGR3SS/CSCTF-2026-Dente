# Cloudflare Deanon: Find the Origin

**Author:** Varenik14  
**Category:** OSINT  
Mission: [Cloudflare Deanon: Find the Origin](https://2026.chronos-security.ro/challenges#Cloudflare%20Deanon%3A%20Find%20the%20Origin-9175)

## Solve

The briefing asked for the clear-web IPv4 address of the server hosting the simulated NestEgg Capital site. I searched FOFA for `title="NestEgg Capital"` and found a candidate on HTTP port 80. I connected directly to that IPv4 and compared the response with the indexed result.

The request returned HTTP 200 from nginx and the page title `NestEgg Capital | Reg. No. NEC-7731-0049`. The ETag `"6ad925a1-115b"` and Last-Modified value also matched FOFA. I recorded the peer IP and headers in [origin-response.txt](files/origin-response.txt).

The check I used was `curl --noproxy '*' -i "http://$ORIGIN_IP/"` with the IPv4 from the search result. The saved response records the result at solve time.

**Flag:** `CSCTF{185.146.86.118}`
