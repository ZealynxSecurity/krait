# Scoring Methodology

For each contest:
1. Load krait-findings.json
2. Compare each Krait finding against official findings
3. Match criteria:
   - EXACT: Same root cause, same code location
   - PARTIAL: Related code area or adjacent issue
   - FP: No matching official finding
4. Calculate:
   - TP = exact matches + partial matches (weighted 0.5)
   - FP = findings with no match
   - Precision = TP / (TP + FP)
   - Recall = TP / total_official
   - F1 = 2 * P * R / (P + R)
