# Experiment 003 — Shamir Threshold Behaviour

## Research Question
Does the implementation correctly realize the expected Shamir threshold property?

## Hypothesis
Reconstruction will fail for any number of shares from 1 to k-1, and will succeed for any number of shares from k to n.

## Independent Variable
Number of shares used for reconstruction.

## Dependent Variables
- Reconstruction success (Boolean)[cite: 1]
- Reconstructed key matches original (Boolean)[cite: 1]
- Reconstruction time[cite: 1]

## Controlled Variables
- n (Total shares generated) = 10[cite: 1]
- Tested thresholds (k) = 3, 5, 8, 10[cite: 1]

## Procedure
1. Generate a dummy key.
2. Split the key into n=10 shares using threshold k.
3. Attempt reconstruction using 1 through 10 shares.
4. Record success, correctness, and time for each attempt.
5. Repeat for k = 3, 5, 8, 10.