### Stage 1 — Test and prepare the demo

**What this does:**
First, I run the test suite to make sure the project is working correctly. Then I generate the synthetic logs that ChronoTrace will investigate.

```powershell
python tests\run_tests.py
python -m chronotrace synth --out demo\input
```

### Stage 2 — Run the investigation and verify the result

**What this does:**
Next, I build the investigation output from the synthetic logs. Then I run verification to confirm that running the same investigation twice produces exactly the same output.

```powershell
python -m chronotrace build --input demo\input --changes demo\input\changes.json --out demo\output
python -m chronotrace verify --input demo\input --changes demo\input\changes.json
```

### Stage 3 — Open the results

**What this does:**
Finally, I open the offline timeline viewer to examine the alerts, clock correction, evidence, and rejected look-alikes.

```powershell
start demo\output\viewer.html
```

### Benchmark

**What this does:**
For the performance test, I generate a larger dataset of about 750,000 events, run the investigation on it, and then display the performance metrics.

```powershell
python -m chronotrace synth --out demo\bench --scale 278
python -m chronotrace build --input demo\bench --changes demo\bench\changes.json --out demo\bench-out
type demo\bench-out\run-metrics.json
```

The latest Windows benchmark processed **750,646 events**, with **638.4 MB peak memory** and **63.526 seconds** runtime.
