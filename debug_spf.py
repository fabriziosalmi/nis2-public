import dns.resolver
import sys

def check_spf(domain):
    print(f"Checking SPF for {domain}...")
    try:
        # Use TCP to avoid UDP truncation issues
        answers = dns.resolver.resolve(domain, 'TXT', tcp=True)
        found = False
        for r in answers:
            # print(f"Raw record strings: {r.strings}")
            txt_val = "".join([s.decode('utf-8') for s in r.strings])
            # print(f"Joined TXT: {txt_val}")
            if "v=spf1" in txt_val:
                print(f"MATCH: SPF found! -> {txt_val[:50]}...")
                found = True
                break
        if not found:
            print("No record matched 'v=spf1'")
    except Exception as e:
        print(f"Error resolving SPF: {e}")

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "mainstreaming.tv"
    check_spf(domain)
