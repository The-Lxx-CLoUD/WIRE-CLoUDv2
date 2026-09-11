<?php

declare(strict_types=1);

$capturesDir = realpath(__DIR__ . '/../captures') ?: (__DIR__ . '/../captures');

function human_bytes(int $bytes): string {
    if ($bytes < 1024) return $bytes . ' B';
    if ($bytes < 1024 * 1024) return round($bytes / 1024, 1) . ' KB';
    return round($bytes / (1024 * 1024), 2) . ' MB';
}

$sessions = [];
if (is_dir($capturesDir)) {
    foreach (glob($capturesDir . '/*.json') as $file) {
        $data = json_decode((string) file_get_contents($file), true);
        if (is_array($data)) {
            $data['_pcap_exists'] = isset($data['pcap_file'])
                && file_exists($capturesDir . '/' . $data['pcap_file']);
            $sessions[] = $data;
        }
    }
    usort($sessions, fn($a, $b) => strcmp($b['created_at'] ?? '', $a['created_at'] ?? ''));
}

$totalPackets = array_sum(array_map(fn($s) => $s['stats']['total'] ?? 0, $sessions));
$totalBytes   = array_sum(array_map(fn($s) => $s['stats']['bytes'] ?? 0, $sessions));
?>
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8">
<title>WIRE-CLOUD :: Reports</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="report.css">
</head>
<body>
<header class="topbar">
  <div class="brand">
    <span class="brand-mark">WC</span>
    <div class="brand-text">
      <span class="brand-name">WIRE<span class="accent">-</span>CLOUD</span>
      <span class="brand-sub">session reports · PHP dashboard</span>
    </div>
  </div>
  <div class="summary">
    <span class="chip">Sessions: <b><?= count($sessions) ?></b></span>
    <span class="chip">Total packets: <b><?= number_format($totalPackets) ?></b></span>
    <span class="chip">Total volume: <b><?= human_bytes((int)$totalBytes) ?></b></span>
  </div>
</header>

<main>
<?php if (empty($sessions)): ?>
  <div class="empty">
    <p>No saved sessions yet.</p>
    <p class="fa">هنوز هیچ جلسه‌ای ذخیره نشده است.</p>
    <p class="hint">Capture traffic in the main WIRE-CLOUD web app, then click
       <b>SAVE SESSION</b> to have it appear here.</p>
  </div>
<?php else: ?>
  <table>
    <thead>
      <tr>
        <th>Session</th>
        <th>Interface</th>
        <th>Filter</th>
        <th>Packets</th>
        <th>Volume</th>
        <th>Top protocols</th>
        <th>PCAP</th>
      </tr>
    </thead>
    <tbody>
    <?php foreach ($sessions as $s):
        $byProto = $s['stats']['by_proto'] ?? [];
        arsort($byProto);
        $top = array_slice($byProto, 0, 4, true);
    ?>
      <tr>
        <td class="mono"><?= htmlspecialchars($s['session'] ?? '—') ?></td>
        <td class="mono"><?= htmlspecialchars($s['interface'] ?? '—') ?></td>
        <td class="mono dim"><?= htmlspecialchars($s['filter'] ?: 'none') ?></td>
        <td class="mono"><?= number_format($s['stats']['total'] ?? 0) ?></td>
        <td class="mono"><?= human_bytes((int)($s['stats']['bytes'] ?? 0)) ?></td>
        <td>
          <?php foreach ($top as $proto => $count): ?>
            <span class="proto-pill proto-<?= strtolower(htmlspecialchars($proto)) ?>">
              <?= htmlspecialchars($proto) ?> · <?= (int)$count ?>
            </span>
          <?php endforeach; ?>
        </td>
        <td>
          <?php if ($s['_pcap_exists']): ?>
            <a class="dl" href="download.php?file=<?= urlencode($s['pcap_file']) ?>">.pcap ⭳</a>
          <?php else: ?>
            <span class="dim">missing</span>
          <?php endif; ?>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
<?php endif; ?>
</main>

<footer>
  <span>WIRE-CLOUD PHP reporting module &middot; reads <code><?= htmlspecialchars($capturesDir) ?></code></span>
</footer>
</body>
</html>
