import dns.resolver
import sys

def check_dmarc(domain):
    print(f"Checking DMARC for {domain}...")
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        found = False
        for r in dmarc_answers:
            print(f"Raw record strings: {r.strings}")
            txt_val = "".join([s.decode('utf-8') for s in r.strings])
            print(f"Joined TXT: {txt_val}")
            if "v=DMARC1" in txt_val:
                print("MATCH: DMARC found!")
                found = True
                break
        if not found:
            print("No record matched 'v=DMARC1'")
    except Exception as e:
        print(f"Error resolving DMARC: {e}")

if __name__ == "__main__":
    domain = sys.argv[1] if len(sys.argv) > 1 else "mainstreaming.tv"
    check_dmarc(domain)
