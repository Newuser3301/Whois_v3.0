import ipaddress
import re

CLOUDFLARE_IPV4_RANGES = [
    ipaddress.ip_network(network)
    for network in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
    )
]


def normalize_domain(value):
    """Foydalanuvchi kiritgan domenni xavfsiz, DNSga mos ko'rinishga keltirish."""
    domain = (value or "").strip()
    if not domain:
        raise ValueError("Iltimos, domen kiriting!")

    domain = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", domain)
    domain = domain.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    domain = domain.split("@")[-1].split(":", 1)[0].strip().rstrip(".").lower()

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Domen nomi noto'g'ri formatda") from exc

    if len(domain) > 253:
        raise ValueError("Domen nomi juda uzun")
    if not re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+", domain):
        raise ValueError("Domen formati noto'g'ri. Masalan: example.com")

    return domain


def is_cloudflare_ip(ip_value):
    """IP manzil Cloudflare IPv4 diapazonlariga kirishini tekshiradi."""
    try:
        ip_addr = ipaddress.ip_address(ip_value)
    except ValueError:
        return False
    return any(ip_addr in network for network in CLOUDFLARE_IPV4_RANGES)
