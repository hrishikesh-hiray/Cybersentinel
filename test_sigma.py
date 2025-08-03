# test_sigma.py

from agents.sigma_engine import scan_with_sigma

# Simulated log data
log = "User executed: cmd.exe /c whoami"

# Run Sigma detection
matches = scan_with_sigma(log)

# Print result
print("Matches:", matches)