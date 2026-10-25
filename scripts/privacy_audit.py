import json
from pathlib import Path
from scipy.stats import beta
from pseudonymizer import Pseudonymizer

def calculate_clopper_pearson(n, x, alpha=0.05):
    """Calculate Clopper-Pearson exact confidence interval."""
    lower = beta.ppf(alpha/2, x, n - x + 1) if x > 0 else 0.0
    upper = beta.ppf(1 - alpha/2, x + 1, n - x) if x < n else 1.0
    return lower, upper

def audit_cross_task_linkability():
    print("=== Privacy & Statistics Audit ===\n")
    
    secret_key = Path(".secrets/hmac.key").read_bytes()
    dummy_hostnames = {"mail", "server1"}
    test_ips = [f"192.168.1.{i}" for i in range(1, 21)]  # 20 test IPs
    
    # 1. Global-HMAC Cross-Task Linkability
    # In Global mode, task_id is ignored, so we just instantiate once
    p_global = Pseudonymizer(mode="global_hmac", secret_key=secret_key, hostnames=dummy_hostnames)
    global_tokens_task1 = {ip: p_global._token("IP", ip, "2026-01-01T00:00:00Z") for ip in test_ips}
    global_tokens_task2 = {ip: p_global._token("IP", ip, "2026-01-01T00:00:00Z") for ip in test_ips}
    
    l_cross_global = 0
    for ip in test_ips:
        if global_tokens_task1[ip] == global_tokens_task2[ip]:
            l_cross_global += 1
    l_cross_global_rate = l_cross_global / len(test_ips)

    # 2. Task-Scoped HMAC Cross-Task Linkability
    p_task1 = Pseudonymizer(mode="task_scoped", secret_key=secret_key, hostnames=dummy_hostnames, task_id="task_001")
    p_task2 = Pseudonymizer(mode="task_scoped", secret_key=secret_key, hostnames=dummy_hostnames, task_id="task_002")
    
    task_tokens_task1 = {ip: p_task1._token("IP", ip, "2026-01-01T00:00:00Z") for ip in test_ips}
    task_tokens_task2 = {ip: p_task2._token("IP", ip, "2026-01-01T00:00:00Z") for ip in test_ips}
    
    l_cross_task = 0
    for ip in test_ips:
        if task_tokens_task1[ip] == task_tokens_task2[ip]:
            l_cross_task += 1
    l_cross_task_rate = l_cross_task / len(test_ips)

    print(f"--- Token Linkability (L_cross) ---")
    print(f"Global-HMAC Cross-Task Equality Rate: {l_cross_global_rate:.2f} (Expected: 1.00)")
    print(f"Task-Scoped Cross-Task Equality Rate: {l_cross_task_rate:.2f} (Expected: 0.00)")

    # 3. Statistical Confidence Interval for LLM Experiment (Recall)
    # n = 5 positive samples, x = 5 successful identifications (F1=1.0)
    n = 5
    x = 5
    lower, upper = calculate_clopper_pearson(n, x)
    
    print(f"\n--- Statistical Confidence Interval (Clopper-Pearson) ---")
    print(f"Positive Samples (n): {n}")
    print(f"Successful Identifications (x): {x}")
    print(f"95% CI for Recall: [{lower:.3f}, {upper:.3f}]")
    print(f"Lower bound = {lower:.3f}")

if __name__ == "__main__":
    audit_cross_task_linkability()
