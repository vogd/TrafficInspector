#!/usr/bin/env python3
"""POC inspection cost model (us-east-1 list prices).
Fixed = endpoint + TLS + TGW attachment hours. Variable = NFW + TGW data processing.
NAT Gateway is service-chained with NFW => waived. Marginal $/GB is volume-independent.
"""
HOURS = 720
FW_HR, TLS_HR, TGW_HR = 0.395, 0.489, 0.05      # per hour (FW/TLS are per AZ)
FW_GB, TGW_GB, ATD_GB = 0.065, 0.04, 0.005      # TGW_GB = 2 hops x $0.02


def monthly(gb_day, az=2, tls=True, pct=1.0, atd=False, attachments=2):
    gb = gb_day * 30 * pct
    fixed = az * FW_HR * HOURS + (az * TLS_HR * HOURS if tls else 0) + attachments * TGW_HR * HOURS
    per_gb = FW_GB + TGW_GB + (ATD_GB if atd else 0)
    var = gb * per_gb
    total = fixed + var
    return total, fixed, var, (total / gb if gb else 0), per_gb


VOLUMES = [("10 GB/day", 10), ("100 GB/day", 100), ("1 TB/day", 1_000), ("10 TB/day", 10_000),
           ("100 TB/day", 100_000), ("1 PB/day", 1_000_000)]

if __name__ == "__main__":
    print(f"{'Volume':<12}{'Total $/mo':>15}{'Fixed':>11}{'Variable $/mo':>16}{'Blended $/GB':>14}{'Increment':>20}")
    prev = None
    for name, gbd in VOLUMES:
        total, fixed, var, blended, mg = monthly(gbd)
        inc = "-" if prev is None else f"+${total - prev:,.0f}/mo"
        print(f"{name:<12}{total:>15,.0f}{fixed:>11,.0f}{var:>16,.0f}{blended:>14.4f}{inc:>20}")
        prev = total
    print(f"\nMarginal (incremental) cost per GB, flat at any volume: ${FW_GB + TGW_GB:.3f}/GB")
    print("TLS inspection adds NO per-GB charge (hourly only). Set pct<1.0 for selective deep-inspection.")
