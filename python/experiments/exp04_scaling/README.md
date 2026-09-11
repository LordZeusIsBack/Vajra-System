# Experiment 04 - System Scaling

## Research Question
How do share generation, encryption, and reconstruction times scale as the number of centres (n) and the threshold (k) increase?

## Hypothesis
Time and resource usage will increase linearly (or quadratically, depending on your architecture) as $n$ and $k$ grow.

## Environment
* CPU: AMD64 Family 23 Model 96 Stepping 1, AuthenticAMD
* RAM: 15.42 GB
* OS: Window 11
* Python Version: 3.12.12

## Independent Variables
* Number of centres ($n$)
* Threshold ($k$)

## Dependent Variables
* Share generation time
* Encryption time
* Reconstruction time
* Memory usage
* Data transferred
* Number of IPFS objects

## Controlled Variables
* Payload/PDF size (e.g., fixed at 1MB)
* $T_{ops}$ for the RSW puzzle
* Hardware environment