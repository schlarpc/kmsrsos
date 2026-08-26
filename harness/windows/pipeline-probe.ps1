
$ErrorActionPreference = "Stop"
$bind  = [Convert]::FromBase64String("BQALExAAAACgAAAAAgAAANAW0BYAAAAAAwAAAAAAAQB1IchRToRQR7DY7CVVVbwGAQAAAARdiIrrHMkRn+gIACsQSGACAAAAAQABAHUhyFFOhFBHsNjsJVVVvAYBAAAAMwVxcbq+N0mDGbXb75zMNgEAAAACAAEAdSHIUU6EUEew2OwlVVW8BgEAAAAsHLdsEphARQMAAAAAAAAAAQAAAA==")
$alter = [Convert]::FromBase64String("BQAOExAAAABIAAAAAgAAANAW0BZKyI5bAQAAAAAAAQB1IchRToRQR7DY7CVVVbwGAQAAAARdiIrrHMkRn+gIACsQSGACAAAA")
$req1  = [Convert]::FromBase64String("BQAAAxAAAAAkAQAAAgAAAAwBAAAAAAAABAEAAAQBAAAAAAYA9Sc7Dp7CohLinuHIKl+H2SfCXOIDz6GRgFFl/TtgXFoxhOqIi5BjKUf5f+0h0dsqWhq8/nF9a5KnuULF7Qb7CEOVQgcv6NsbAcmXKTwikL3NOCuwlKQzvbhVkduQPMtqIk9rzUdLmWaCUN73qKUW+wzC8TixdFNKpfLX4rcR+lVpZBDaISM1Pnl7jR4EWrJ9PUKC36LWdjYMxyY5thqInPok5lKNqRf6SYQWaOfRJ0bDW3GS6Cx2gG3XYuYVSygj0n8W9AZsycPliIR6PI+0FSDZlvdSa0l4wmn2pL1jOiOWf2zqCVI+Tj8J3jhlYkgOTMd8ULZpck6tZRVB98O8cQ==")
$req2  = [Convert]::FromBase64String("BQAAAxAAAAAkAQAAAwAAAAwBAAAAAAAABAEAAAQBAAAAAAYA9Sc7Dp7CohLinuHIKl+H2SfCXOIDz6GRgFFl/TtgXFoxhOqIi5BjKUf5f+0h0dsqWhq8/nF9a5KnuULF7Qb7CEOVQgcv6NsbAcmXKTwikL3NOCuwlKQzvbhVkduQPMtqIk9rzUdLmWaCUN73qKUW+wzC8TixdFNKpfLX4rcR+lVpZBDaISM1Pnl7jR4EWrJ9PUKC36LWdjYMxyY5thqInPok5lKNqRf6SYQWaOfRJ0bDW3GS6Cx2gG3XYuYVSygj0n8W9AZsycPliIR6PI+0FSDZlvdSa0l4wmn2pL1jOiOWf2zqCVI+Tj8J3jhlYkgOTMd8ULZpck6tZRVB98O8cQ==")

$c = New-Object System.Net.Sockets.TcpClient
$c.NoDelay = $true          # client side must not itself coalesce the probe
$kms = if ($env:KMS_HOST) { $env:KMS_HOST } else { "10.0.2.2" }
$c.Connect($kms, 1688)
$s = $c.GetStream()
$buf = New-Object byte[] 4096

function Step($data) {
  $s.Write($data, 0, $data.Length); $s.Flush()
  $n = $s.Read($buf, 0, $buf.Length)
  return $n
}

Step $bind  | Out-Null
Step $alter | Out-Null

# The measurement: two complete requests in ONE write. If the driver answers
# them with two back-to-back writes, Nagle has a second small write to hold.
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$both = New-Object byte[] ($req1.Length + $req2.Length)
[Array]::Copy($req1, 0, $both, 0, $req1.Length)
[Array]::Copy($req2, 0, $both, $req1.Length, $req2.Length)
$s.Write($both, 0, $both.Length); $s.Flush()

$total = 0
while ($total -lt 600 -and $sw.ElapsedMilliseconds -lt 5000) {
  $n = $s.Read($buf, 0, $buf.Length)
  if ($n -le 0) { break }
  $total += $n
  "read {0,4} bytes at {1,8:N3} ms (total {2})" -f $n, $sw.Elapsed.TotalMilliseconds, $total
}
"TOTAL $total bytes in {0:N3} ms" -f $sw.Elapsed.TotalMilliseconds
$c.Close()
