# Experiment 09 — Release Time Relative to the Scheduled Start

## Research Question
In an end-to-end ceremony (lock → upload → wait → centers → coordinator with
the drand gate), when does the exam paper become available relative to the
scheduled start time?

## Background (Outstanding Evidence item 1)
`T_ops` is calibrated to the whole interval between locking and the
scheduled start, but the coordinator runs `vajra solve` — all `T_ops`
squarings — only after the drand gate opens. On calibration-class hardware
the paper should therefore appear about one lock duration *after* the
start. This was found by reading the code; this experiment measures it.

## Hypothesis
`pdf_ready − scheduled_start ≈ L` (one lock duration), plus the gate offset
of up to one drand period, on the machine that calibrated the puzzle.

## Independent Variable
Lock duration L (`--lock-seconds`, default 300 s).

## Dependent Variables
`pdf_ready − scheduled_start`, `pdf_ready − beacon_publish`,
`(pdf_ready − scheduled_start) / L`, solve time, and whether the recovered
PDF equals the input.

## Timeline columns
| column | meaning |
| --- | --- |
| `scheduled_start` | lock time + L as computed by the pipeline |
| `beacon_publish` | genesis + (R − 1)·period: when the beacon publishes the target round R |
| `gate_time` | genesis + R·period: when the coordinator's clock check passes (the implementation's round numbering is one period late; see the paper, §III-B) |
| `gate_passed`, `solve_started`, `pdf_ready` | from `combine_shares_to_pdf(stage_times=…)` |

The `mode` column is always `legacy` (squarings after the gate).

## Procedure
```bash
# In-memory storage, real clock check with mocked relay responses:
python run_release_timing.py --lock-seconds 300

# Real Kubo nodes and the live drand relays:
python ../kubo_cluster.py init --nodes 3 && python ../kubo_cluster.py start
python run_release_timing.py --lock-seconds 300 --ipfs real --drand live --reps 3

# Through the running Source Vault service (POST /api/v1/lock):
python run_release_timing.py --lock-seconds 300 --ipfs real --drand live \
    --service-url http://127.0.0.1:8000 --keys-dir ../../keys
```
Run the experiment on the machine whose speed is recorded in the puzzle
(the one that ran `vajra generate`); on a faster or slower machine the delay
scales accordingly.

## Check run (development sandbox, not for the paper)
L = 60 s, 3 local Kubo nodes, clock gate with mocked relays, 2-vCPU cloud
VM: the paper was available 63.9 s after the scheduled start (1.07 L), and
the recovered PDF was identical to the input. The live-relay mode could not
be run from the sandbox.
