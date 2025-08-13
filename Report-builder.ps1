function Report-builder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$InputFile,

        [string]$JsReportPath = ".\report_js.html",
        [string]$FallbackReportPath = ".\report_fallback.html"
    )

    
    function _H([string]$s){
        if ($null -eq $s) { return "" }
        
        $s = $s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;')
        $s = $s.Replace('"','&quot;').Replace("'",'&#39;')
        return $s
    }

    function Get-GroupKey([string]$name) {
        if ([string]::IsNullOrWhiteSpace($name)) { return "Unknown" }
        $known = @(
            'APPLE-ID','PASSWORD','TEAM-ID','USERNAME','USER','KEY','TOKEN','CLIENTID','CLIENT-ID',
            'CLIENTSECRET','CLIENT-SECRET','SECRET','CONNECTION','CONN','URL','HOST','PORT','ID'
        )
        $parts = $name -split '-'
        if ($parts.Count -le 1) { return $name }
        for ($i = $parts.Count - 1; $i -ge 1; $i--) {
            $suffix = ($parts[$i..($parts.Count-1)] -join '-').ToUpperInvariant()
            if ($known -contains $suffix) {
                return ($parts[0..($i-1)] -join '-')
            }
        }
        return ($parts[0..($parts.Count-2)] -join '-')
    }

    
    if (-not (Test-Path $InputFile)) { throw "Input file not found: $InputFile" }
    $lines = Get-Content -Path $InputFile -ErrorAction Stop
    $rows  = foreach ($ln in $lines) {
        if ([string]::IsNullOrWhiteSpace($ln)) { continue }
        try { $obj = $ln | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        [pscustomobject]@{
            SubscriptionName = [string]$obj.SubscriptionName
            ResourceGroup    = [string]$obj.ResourceGroup
            ResourceName     = [string]$obj.ResourceName
            ResourceType     = [string]$obj.ResourceType
            SecretName       = [string]$obj.SecretName
            SecretValue      = [string]$obj.SecretValue
            GroupKey         = Get-GroupKey([string]$obj.SecretName)
        }
    }
    if (-not $rows -or $rows.Count -eq 0) { throw "No valid rows parsed from $InputFile" }

   
    $bySub = @{}
    foreach ($r in $rows) {
        $sub = $r.SubscriptionName; $rg = $r.ResourceGroup; $rn = $r.ResourceName; $gk = $r.GroupKey
        if (-not $bySub.ContainsKey($sub)) { $bySub[$sub] = @{} }
        if (-not $bySub[$sub].ContainsKey($rg)) { $bySub[$sub][$rg] = @{} }
        if (-not $bySub[$sub][$rg].ContainsKey($rn)) { $bySub[$sub][$rg][$rn] = @{} }
        if (-not $bySub[$sub][$rg][$rn].ContainsKey($gk)) { $bySub[$sub][$rg][$rn][$gk] = @() }
        $bySub[$sub][$rg][$rn][$gk] += ,$r
    }

    
    $css = @'
<style>
:root{
  --bg:#0B1020; --card:#12182C; --muted:#8EA0C0; --text:#E8EEFF; --accent:#6EA8FE; --accent2:#79F2C0; --warn:#F9C74F;
  --border:#253055; --red:#ff6b6b;
}
*{box-sizing:border-box}
body{margin:24px;font-family:Segoe UI,Roboto,Arial,sans-serif;background:linear-gradient(160deg,#0b1020 0%,#151b34 100%);color:var(--text)}
h1{font-weight:700;letter-spacing:.3px;margin:0 0 16px}
.subtitle{color:var(--muted);margin-bottom:18px}
.toolbar{display:flex;gap:12px;align-items:center;margin:12px 0 18px}
.search{flex:1; position:relative}
.search input{
  width:100%; padding:12px 40px 12px 12px; border-radius:12px; border:1px solid var(--border); background:#0e1430; color:var(--text);
  outline:none; transition:border .2s, box-shadow .2s;
}
.search input:focus{border-color:var(--accent); box-shadow:0 0 0 3px rgba(110,168,254,.1)}
.count{padding:10px 12px;border:1px solid var(--border);border-radius:10px;background:#0e1430;color:var(--muted)}
.badge{display:inline-flex;align-items:center;gap:6px;padding:4px 8px;border:1px solid var(--border);border-radius:999px;background:#10183a;color:var(--muted);font-size:12px}
.table-wrap{padding:8px 16px 16px}
table{width:100%;border-collapse:collapse;overflow:hidden;border-radius:12px}
th,td{padding:10px 12px;border-bottom:1px dashed rgba(255,255,255,.06);vertical-align:top}
th{position:sticky;top:0;background:#11193a;color:#cfe1ff;text-align:left;font-weight:600;cursor:pointer}
tr:hover td{background:rgba(255,255,255,.02)}
.kv{display:flex;align-items:center;gap:8px}
.secret{font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; background:#0d1430; padding:6px 8px; border-radius:8px; border:1px solid var(--border)}
.secret[data-masked="false"]{filter:blur(4px)}
.btn{
  border:1px solid var(--border); background:#0f1640; color:var(--text); padding:6px 9px; border-radius:8px; cursor:pointer;
  transition:transform .08s ease, background .2s, border .2s; font-size:12px
}
.btn:hover{background:#161f4d}
.btn:active{transform:scale(.98)}
.row-hide{display:none !important}
.highlight{background:linear-gradient(90deg, rgba(121,242,192,.15), rgba(110,168,254,.15)); border-radius:6px; padding:0 2px}
.note{color:var(--muted);font-size:12px}
.footer{margin-top:24px;color:var(--muted)}
.rotate{transform:rotate(90deg);transition:transform .2s}
.acc.open .rotate{transform:rotate(270deg)}
/* Accordion bodies hidden by default; open toggles them */
.acc-body{display:none;}
.acc.open .acc-body{display:block;}
/* Details fallback */
details summary{cursor:pointer; list-style:none; padding:12px 16px; background:#1a2242; border-bottom:1px solid var(--border); color:#cfe1ff; font-weight:600; border-radius:8px}
details{border:1px solid var(--border); border-radius:12px; background:var(--card); margin-bottom:12px; overflow:hidden}
/* Level-specific header colors */
.head-sub   { background: #0d2a4d; border-left: 4px solid #3b82f6; }  /* Subscription */
.head-rg    { background: #133a2c; border-left: 4px solid #22c55e; }  /* Resource Group */
.head-kv    { background: #3b1634; border-left: 4px solid #e879f9; }  /* Key Vault (resource) */
.head-group { background: #2f240e; border-left: 4px solid #f59e0b; }  /* Group (pairs) */

.head-sub:hover, .l1 .acc-head:hover      { filter: brightness(1.08); }
.head-rg:hover,  .l2 .acc-head:hover      { filter: brightness(1.08); }
.head-kv:hover,  .l3 .acc-head:hover      { filter: brightness(1.08); }
.head-group:hover,.l4 .acc-head:hover     { filter: brightness(1.08); }

/* Fallback <details> titles (no-JS) */
summary.sub    { background: #0d2a4d; border-left: 4px solid #3b82f6; }
summary.rg     { background: #133a2c; border-left: 4px solid #22c55e; }
summary.kv     { background: #3b1634; border-left: 4px solid #e879f9; }
summary.group  { background: #2f240e; border-left: 4px solid #f59e0b; }

</style>
'@

    
    $js = @'
<script>
(function(){
  const on=(t,sel,fn)=>document.addEventListener(t,e=>{const el=e.target.closest(sel); if(el) fn(e,el);},true);

  // Toggle accordions
  on('click','.acc-head',(e,head)=>{
    const acc=head.closest('.accordion'); if(acc) acc.classList.toggle('open');
  });

  // Sort table by column
  on('click','th.sortable',(e,th)=>{
    const table=th.closest('table'); const idx=+th.dataset.col||0;
    const dir=th.dataset.dir==='asc'?'desc':'asc'; th.dataset.dir=dir;
    const rows=[...table.querySelectorAll('tbody tr')].sort((a,b)=>{
      const av=(a.children[idx]?.innerText||'').toLowerCase();
      const bv=(b.children[idx]?.innerText||'').toLowerCase();
      return av<bv ? (dir==='asc'?-1:1) : av>bv ? (dir==='asc'?1:-1) : 0;
    });
    const tb=table.querySelector('tbody'); rows.forEach(r=>tb.appendChild(r));
  });

  // Copy / Mask buttons
  on('click','.btn-copy', async (e,btn)=>{
    const span=btn.closest('td').querySelector('.secret');
    try{
      await navigator.clipboard.writeText(span?.dataset.raw||span?.textContent||'');
      const t=btn.textContent; btn.textContent='Copied'; btn.classList.add('copy-ok');
      setTimeout(()=>{btn.textContent=t; btn.classList.remove('copy-ok');},900);
    }catch{}
  });
  on('click','.btn-mask',(e,btn)=>{
    const s=btn.closest('td').querySelector('.secret'); if(!s) return;
    const m=s.getAttribute('data-masked')==='true'; s.setAttribute('data-masked', m?'false':'true');
    btn.textContent=m?'Hide':'Show';
  });

  // Search + highlight
  const input=document.getElementById('q'), total=document.getElementById('totalCount'), shown=document.getElementById('shownCount');
  function esc(s){return s.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');}
  function strip(s){return s.replace(/<[^>]*>/g,'');}
  function filter(){
    const term=(input?.value||'').trim(); let cnt=0;
    document.querySelectorAll('tbody tr').forEach(tr=>{
      tr.classList.remove('row-hide'); tr.querySelectorAll('.highlight').forEach(h=>h.outerHTML=h.innerText);
      if(term){
        const re=new RegExp(esc(term),'ig');
        const hit=[...tr.children].some(td=>re.test(strip(td.innerHTML)));
        if(!hit) tr.classList.add('row-hide');
        else [...tr.children].forEach(td=>td.innerHTML=td.innerHTML.replace(re,m=>`<span class="highlight">${m}</span>`));
      }
      if(!tr.classList.contains('row-hide')) cnt++;
    });
    if(shown) shown.textContent=cnt;
  }
  if(input){ input.addEventListener('input', filter); }

  const rows=document.querySelectorAll('tbody tr').length;
  if(total) total.textContent=rows; if(shown) shown.textContent=rows;

  // open first 3 subscriptions by default
  document.querySelectorAll('.accordion.l1').forEach((acc,i)=>{ if(i<3) acc.classList.add('open'); });
})();
</script>
'@

    
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!doctype html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine('<title>Vaulter Report</title>')
    [void]$sb.AppendLine($css)
    [void]$sb.AppendLine('</head><body>')
    [void]$sb.AppendLine('<h1>Vaulter Report</h1>')
	[void]$sb.AppendLine('<h3>By ART, AB-inBev</h3>')
    [void]$sb.AppendLine('<div class="subtitle">Interactive report (search, sort, collapse, copy & mask secrets).</div>')
    [void]$sb.AppendLine('<div class="toolbar">')
    [void]$sb.AppendLine('<div class="search"><input id="q" type="text" placeholder="Search any text... (Subscription, RG, Name, Type, Secret, Value)"></div>')
    [void]$sb.AppendLine('<div class="count"><span class="small">Showing</span> <b id="shownCount">0</b> <span class="small">of</span> <b id="totalCount">0</b></div>')
    [void]$sb.AppendLine('</div>')

    foreach ($sub in ($bySub.Keys | Sort-Object)) {
        $subE = _H($sub)
        [void]$sb.AppendLine('<div class="accordion l1">')
		[void]$sb.AppendLine("<div class='acc-head head-sub'><div class='acc-title'><span class='rotate'>❯</span><b>Subscription ID :</b> <span>$subE</span></div><span class='badge'>RGs: $([int]$bySub[$sub].Count)</span></div>")
        [void]$sb.AppendLine('<div class="acc-body">')

        foreach ($rg in ($bySub[$sub].Keys | Sort-Object)) {
            $rgE = _H($rg)
            [void]$sb.AppendLine('<div class="accordion l2">')
			[void]$sb.AppendLine("<div class='acc-head head-rg'><div class='acc-title'><span class='rotate'>❯</span><b>Resource Group:</b> <span>$rgE</span></div><span class='badge'>Resources: $([int]$bySub[$sub][$rg].Count)</span></div>")
            [void]$sb.AppendLine('<div class="acc-body">')

            foreach ($rn in ($bySub[$sub][$rg].Keys | Sort-Object)) {
                $rnE = _H($rn)
                [void]$sb.AppendLine('<div class="accordion l3">')
				[void]$sb.AppendLine("<div class='acc-head head-kv'><div class='acc-title'><span class='rotate'>❯</span><b>Key Vault:</b> <span>$rnE</span></div><span class='badge'>Groups: $([int]$bySub[$sub][$rg][$rn].Count)</span></div>")
                [void]$sb.AppendLine('<div class="acc-body">')

                foreach ($gk in ($bySub[$sub][$rg][$rn].Keys | Sort-Object)) {
                    $gkE = if ([string]::IsNullOrWhiteSpace($gk)) { 'Ungrouped' } else { _H($gk) }
                    $groupRows = $bySub[$sub][$rg][$rn][$gk]

                    [void]$sb.AppendLine('<div class="accordion l4">')
					[void]$sb.AppendLine("<div class='acc-head head-group'><div class='acc-title'><span class='rotate'>❯</span><b>Section:</b> <span>$gkE</span></div><span class='badge'>Items: $($groupRows.Count)</span></div>")
                    [void]$sb.AppendLine('<div class="acc-body"><div class="table-wrap">')

                    [void]$sb.AppendLine('<table>')
                    [void]$sb.AppendLine('<thead><tr>')
                    $headers = @('Subscription Name','Resource Group','Resource Name','Resource Type','Secret Name','Secret Value','Actions')
                    for ($i=0; $i -lt $headers.Count; $i++) {
                        [void]$sb.AppendLine("<th class=""sortable"" data-col=""$i"">$($headers[$i])</th>")
                    }
                    [void]$sb.AppendLine('</tr></thead><tbody>')

                    foreach ($row in $groupRows) {
                        $sub1 = _H($row.SubscriptionName); $rg1 = _H($row.ResourceGroup)
                        $rn1  = _H($row.ResourceName);    $rt1 = _H($row.ResourceType)
                        $sn1  = _H($row.SecretName)
                        $svRaw = [string]$row.SecretValue; $svE = _H($svRaw)

                        [void]$sb.AppendLine('<tr>')
                        [void]$sb.AppendLine("<td>$sub1</td>")
                        [void]$sb.AppendLine("<td>$rg1</td>")
                        [void]$sb.AppendLine("<td>$rn1</td>")
                        [void]$sb.AppendLine("<td>$rt1</td>")
                        [void]$sb.AppendLine("<td>$sn1</td>")
                        [void]$sb.AppendLine("<td><span class='secret' data-raw='$svE' data-masked='true'>$svE</span></td>")
                        [void]$sb.AppendLine("<td class='kv'><button class='btn btn-mask'>Show</button><button class='btn btn-copy'>Copy</button></td>")
                        [void]$sb.AppendLine('</tr>')
                    }

                    [void]$sb.AppendLine('</tbody></table>')
                    [void]$sb.AppendLine('</div></div>') # table-wrap + acc-body
                    [void]$sb.AppendLine('</div>')       # accordion l4
                }

                [void]$sb.AppendLine('</div></div>') # acc-body + l3
            }

            [void]$sb.AppendLine('</div></div>') # acc-body + l2
        }

        [void]$sb.AppendLine('</div></div>') # acc-body + l1
    }

    [void]$sb.AppendLine('<div class="footer">Generated client-side interactive report. Tip: use the search box to filter and highlight any text.</div>')
    [void]$sb.AppendLine($js)
    [void]$sb.AppendLine('</body></html>')

    
    $sf = New-Object System.Text.StringBuilder
    [void]$sf.AppendLine('<!doctype html>')
    [void]$sf.AppendLine('<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sf.AppendLine('<title>Key Vault Secrets Report (Fallback)</title>')
    [void]$sf.AppendLine($css)
    [void]$sf.AppendLine('</head><body>')
    [void]$sf.AppendLine('<h1>Key Vault Secrets Report</h1>')
    [void]$sf.AppendLine('<div class="subtitle">No-JS fallback (native &lt;details&gt; / &lt;summary&gt;). Use your browser search (Ctrl+F).</div>')

    foreach ($sub in ($bySub.Keys | Sort-Object)) {
        $subE = _H($sub)
        [void]$sf.AppendLine('<details open class="l1">')
		[void]$sf.AppendLine("<summary class='sub'><b>Subscription:</b> $subE</summary>")

        foreach ($rg in ($bySub[$sub].Keys | Sort-Object)) {
            $rgE = _H($rg)
            [void]$sf.AppendLine('<details class="l2">')
			[void]$sf.AppendLine("<summary class='rg'><b>Resource Group:</b> $rgE</summary>")

            foreach ($rn in ($bySub[$sub][$rg].Keys | Sort-Object)) {
                $rnE = _H($rn)
                [void]$sf.AppendLine('<details class="l3">')
				[void]$sf.AppendLine("<summary class='kv'><b>Key Vault:</b> $rnE</summary>")

                foreach ($gk in ($bySub[$sub][$rg][$rn].Keys | Sort-Object)) {
                    $gkE = if ([string]::IsNullOrWhiteSpace($gk)) { 'Ungrouped' } else { _H($gk) }
                    $groupRows = $bySub[$sub][$rg][$rn][$gk]
                    [void]$sf.AppendLine('<details class="l4">')
					[void]$sf.AppendLine("<summary class='group'><b>Group:</b> $gkE <span class='badge'>Items: $($groupRows.Count)</span></summary>")
                    [void]$sf.AppendLine('<div class="table-wrap">')

                    [void]$sf.AppendLine('<table>')
                    [void]$sf.AppendLine('<thead><tr>')
                    $headers = @('Subscription Name','Resource Group','Resource Name','Resource Type','Secret Name','Secret Value')
                    foreach ($h in $headers) { [void]$sf.AppendLine("<th>$h</th>") }
                    [void]$sf.AppendLine('</tr></thead><tbody>')

                    foreach ($row in $groupRows) {
                        $sub1 = _H($row.SubscriptionName); $rg1 = _H($row.ResourceGroup)
                        $rn1  = _H($row.ResourceName);    $rt1 = _H($row.ResourceType)
                        $sn1  = _H($row.SecretName);      $sv1 = _H([string]$row.SecretValue)
                        [void]$sf.AppendLine('<tr>')
                        [void]$sf.AppendLine("<td>$sub1</td><td>$rg1</td><td>$rn1</td><td>$rt1</td><td>$sn1</td><td><pre class='secret' data-masked='true'>$sv1</pre></td>")
                        [void]$sf.AppendLine('</tr>')
                    }

                    [void]$sf.AppendLine('</tbody></table>')
                    [void]$sf.AppendLine('</div></details>') # l4
                }

                [void]$sf.AppendLine('</details>') # l3
            }

            [void]$sf.AppendLine('</details>') # l2
        }

        [void]$sf.AppendLine('</details>') # l1
    }

    [void]$sf.AppendLine('<div class="footer">Generated fallback report (no JavaScript required).</div>')
    [void]$sf.AppendLine('</body></html>')

   
    $utf8Bom = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($JsReportPath, $sb.ToString(), $utf8Bom)
    [System.IO.File]::WriteAllText($FallbackReportPath, $sf.ToString(), $utf8Bom)

    Write-Host "[+] Wrote JS report:       $JsReportPath" -ForegroundColor Green
    Write-Host "[+] Wrote Fallback report: $FallbackReportPath" -ForegroundColor Green
}
