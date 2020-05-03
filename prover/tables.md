# Tables Pre-calculation
The most time consuming part of a ZKSnark proof calculation is the scalar multiplication of elliptic curve points. Direct mechanism accumulates each multiplication. However, prover only needs the total accumulation.

There are two potential improvements to the naive approach:

1. Apply Strauss-Shamir method (https://stackoverflow.com/questions/50993471/ec-scalar-multiplication-with-strauss-shamir-method).
2. Leave the doubling operation for the last step

Both options can be combined. 

In the following table, we show the results of using the naive method, Srauss-Shamir and Strauss-Shamir + No doubling. These last two options are repeated for different table grouping order.

There are 5000 G1 Elliptical Curve Points, and the scalars are 254 bits (BN256 curve). 

There may be some concern on the additional size of the tables since they need to be loaded into a smartphone during the proof, and the time required to load these tables may exceed the benefits. If this is a problem, another althernative is to compute the tables during the proof itself. Depending on the Group Size, timing may be better than the naive approach.


| Algorithm | GS 2 | GS 3 | GS 4 | GS 5 | GS 6 | GS 7 | GS 8 | GS 9 | 
|---|---|---|---|---|---|---|---|---|
| Naive | 6.63s | - | - | - | - | - |  - | - |
| Strauss |  13.16s | 9.03s | 6.95s | 5.61s | 4.91s | 4.26s | 3.88s | 3.54 s |
| Strauss + Table Computation | 16.13s | 11.32s | 8.47s | 7.10s | 6.2s | 5.94s | 6.01s | 6.69s |
| No Doubling | 3.74s | 3.00s | 2.38s | 1.96s | 1.79s | 1.54s | 1.50s | 1.44s|
| No Doubling + Table Computation  | 6.83s | 5.1s | 4.16s | 3.52s| 3.22s | 3.21s | 3.57s | 4.56s |

