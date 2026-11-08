
(()=>{'use strict';
const iconPaths={grid:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',update:'<path d="M20 7v5h-5M4 17v-5h5"/><path d="M5 9a8 8 0 0 1 13-3l2 2M4 16l2 2a8 8 0 0 0 13-3"/>',shield:'<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/><path d="m9 12 2 2 4-4"/>',key:'<circle cx="8" cy="15" r="4"/><path d="m10.5 12 9-9 2 2-2.5 2.5-2-2-2.5 2.5 2 2-2.5 2.5"/>',globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a16 16 0 0 1 0 18M12 3a16 16 0 0 0 0 18"/>',folder:'<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v10H3Z"/>',activity:'<path d="M3 12h4l3-7 4 14 3-7h4"/>',sliders:'<path d="M4 7h16M4 17h16"/><circle cx="9" cy="7" r="3" fill="var(--surface)"/><circle cx="16" cy="17" r="3" fill="var(--surface)"/>',server:'<rect x="3" y="3" width="18" height="8" rx="2"/><rect x="3" y="13" width="18" height="8" rx="2"/><path d="M7 7h.01M7 17h.01"/>',info:'<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/>',check:'<path d="m4 12 5 5L20 6"/>',alert:'<path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5M12 17h.01"/>',clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l4 2"/>',search:'<circle cx="10" cy="10" r="7"/><path d="m15 15 6 6"/>',bolt:'<path d="m13 2-9 12h7l-1 8 10-12h-7Z"/>',eye:'<path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',external:'<path d="M14 4h6v6M10 14 20 4"/><path d="M20 14v6H4V4h6"/>',file:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M8 13h8M8 17h6"/>',arrow:'<path d="M5 12h14m-6-6 6 6-6 6"/>',lock:'<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',wifi:'<path d="M2 9a15 15 0 0 1 20 0M5 12a10 10 0 0 1 14 0M8 15a6 6 0 0 1 8 0M12 19h.01"/>'};
const ic=(n,s=18)=>`<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${iconPaths[n]||iconPaths.info}</svg>`;
const esc=v=>String(v??'').replace(/[&<>"']/g,x=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[x]));
const configs=[
 ['KALI_MCP_ALLOWED_CIDRS','Scope','cidrs','127.0.0.1/32','IP e reti consentiti con Allow all disattivato'],['KALI_MCP_DENIED_CIDRS','Scope','cidrs','192.168.137.0/24','Reti sempre escluse; priorità massima'],['KALI_MCP_ALLOW_ALL_TARGETS','Scope','bool','false','Consenti tutti i target tranne blacklist'],
 ['KALI_MCP_ALLOW_HOST_EXEC','Permessi','bool','false','Limite di deployment per comandi host'],['KALI_MCP_ALLOW_HOST_ROOT','Permessi','bool','false','Limite di deployment per root host'],['KALI_MCP_ALLOW_MCP_HOST_EXEC','Permessi','bool','false','Consenti esecuzione host ai client MCP autorizzati'],['KALI_MCP_ALLOW_MCP_ROOT','Permessi','bool','false','Consenti root host ai client MCP autorizzati'],['KALI_MCP_ALLOW_PACKAGE_INSTALL','Permessi','bool','false','Permetti installazione di pacchetti'],['KALI_MCP_ALLOW_NETWORK_CHANGES','Permessi','bool','false','Permetti modifiche alle interfacce di rete'],['KALI_MCP_ALLOW_MCP_UPDATES','Permessi','bool','true','Permetti aggiornamenti richiesti via MCP'],
 ['KALI_MCP_API_HEADER_ENABLED','Autenticazione','bool','true','API Bearer abilitati insieme a OAuth'],
 ['KALI_MCP_RELEASE_CHANNEL','Aggiornamenti','channel','beta','Canale delle release'],['KALI_MCP_UPDATE_CHECK_SECONDS','Aggiornamenti','number','21600','Intervallo verifica aggiornamenti (minimo 900 s)'],['KALI_MCP_MAX_JOB_SECONDS','Job','number','300','Timeout dei job (da 5 a 3600 s)'],
 ['KALI_MCP_PORT','Rete','number','8787','Porta esposta dal Core'],['KALI_MCP_BIND_ADDRESS','Rete','text','127.0.0.1','Indirizzo bind del servizio HTTP'],['KALI_MCP_PUBLIC_URL','Rete','url','https://kali-mcp.warebench.com','Indirizzo pubblico canonico']
];
const internal=['KALI_MCP_BROWSER_ORIGINS','KALI_MCP_SUPERUSER_FILE','KALI_MCP_AGENT_GID','KALI_MCP_AGENT_GROUP','KALI_MCP_HOST_USER','KALI_MCP_BROKER_SOCKET','KALI_MCP_HOST_AGENT','KALI_MCP_REQUIRE_SUPERUSER','KALI_MCP_ACCESS_MODE','KALI_MCP_REPO','KALI_MCP_DATA_DIR','KALI_MCP_ADMIN_PASSWORD'];
const cfg=Object.fromEntries(configs.map(x=>[x[0],x[3]]));
const nav=[['overview','grid','Panoramica'],['updates','update','Aggiornamenti'],['scope','shield','Scope & reti'],['permissions','key','Permessi'],['clients','server','Client & token'],['cors','globe','Origini CORS'],['files','folder','File & job'],['logs','activity','Audit e attività'],['settings','sliders','Tutte le variabili'],['lab','eye','Guida']];
const runtime=[['host_exec','Host Exec','Esecuzione di comandi sull’host','KALI_MCP_ALLOW_HOST_EXEC'],['host_root','Host Root','Esecuzione con privilegi root','KALI_MCP_ALLOW_HOST_ROOT'],['package_install','Installazione pacchetti','Gestione pacchetti sul sistema','KALI_MCP_ALLOW_PACKAGE_INSTALL'],['network_changes','Modifiche rete','Gestione delle interfacce','KALI_MCP_ALLOW_NETWORK_CHANGES'],['mcp_updates','MCP Updates','Aggiornamenti richiesti dai client MCP','KALI_MCP_ALLOW_MCP_UPDATES']];
const state={page:'overview',theme:'dark',cfg,dirty:false,mode:'allowlist',draftAllowed:cfg.KALI_MCP_ALLOWED_CIDRS,draftDenied:cfg.KALI_MCP_DENIED_CIDRS,testIP:'192.168.0.1',search:'',installed:'v0.1.0-beta.11',latest:'v0.1.0-beta.12',updateIndex:-1,updateRun:'idle',failNext:false,checked:false,history:[],runtime:{host_exec:false,host_root:false,package_install:false,network_changes:false,mcp_updates:true},origins:['https://llm.davidecasalin.it'],api:[{name:'llama-ui · Demo',id:'tok_demo_82cf',expires:'2026-12-08',status:'Attivo'},{name:'CLI automation · Demo',id:'tok_demo_f18b',expires:'2026-12-20',status:'Attivo'}],oauth:[{name:'llama-ui OAuth · Demo',id:'oauth_c2a1',status:'Attivo'}],files:[{name:'scan-results.txt',size:28414,mode:'Base64',status:'Completato'}],events:[],tests:{update:false,scope:false,cors:false,settings:false},jobSelected:'job-2026-11-08-01',originDraft:'',tokenReveal:'',t0:Date.now()};
const steps=['Richiesta ricevuta','Download release','Verifica SHA256','Backup configurazione','Installazione Core','Riavvio servizi','Healthcheck Core e Agent','Completato'];
const sampleJobs=[{id:'job-2026-11-08-01',tool:'core-upgrade',actor:'webui',state:'Completato',time:'18:42:15'},{id:'job-2026-11-08-02',tool:'tools_execute:nmap',actor:'mcp:api:llama-ui',state:'Bloccato',time:'18:34:02'},{id:'job-2026-11-08-03',tool:'tools_search',actor:'mcp:oauth:llama-ui',state:'Completato',time:'18:27:40'}];
const log=(actor,action,detail,status='OK')=>{state.events.unshift({at:new Date().toLocaleTimeString('it-IT',{hour12:false}),actor,action,detail,status});state.events=state.events.slice(0,35)};
log('system','staging.init','Dati dimostrativi caricati');log('mcp:api:llama-ui','scope.denied','Target 192.168.137.42 escluso','DENIED');
const badge=(txt,type='blue')=>`<span class="badge ${type}">${esc(txt)}</span>`;
const card=(body,cls='')=>`<article class="card ${cls}">${body}</article>`;
const head=(k,title,desc,right='')=>`<div class="page-head"><div><div class="eyebrow">${esc(k)}</div><h1>${esc(title)}</h1><p>${desc}</p></div>${right?`<div class="head-buttons">${right}</div>`:''}</div>`;
const button=(label,action,variant='ghost',extra='')=>`<button class="btn ${variant}" data-action="${action}" ${extra}>${label}</button>`;
const section=(title,desc='',right='')=>`<div class="section-title"><div><h2>${esc(title)}</h2>${desc?`<p>${esc(desc)}</p>`:''}</div>${right}</div>`;
function side(){document.getElementById('side').innerHTML=`<div class="brand"><div class="brand-logo">${ic('shield',21)}</div><div><div class="brand-name">KALI MCP</div><div class="brand-sub">Control center</div></div></div><div class="nav"><div class="navlabel">WORKSPACE</div>${nav.slice(0,8).map(([id,icon,label])=>`<button class="${state.page===id?'active':''}" data-action="nav" data-value="${id}">${ic(icon,17)}<span>${label}</span></button>`).join('')}<div class="navlabel">CONFIGURAZIONE</div>${nav.slice(8).map(([id,icon,label])=>`<button class="${state.page===id?'active':''}" data-action="nav" data-value="${id}">${ic(icon,17)}<span>${label}</span></button>`).join('')}</div><div class="side-foot"><small>Istanza protetta</small><div class="ident"><span>●</span> Core ${state.coreOnline?'online':'non raggiungibile'} · Agent ${state.agentOnline?'online':'offline'}</div><div class="version">${esc(state.installed)} · produzione</div></div>`;document.getElementById('crumb').textContent=nav.find(v=>v[0]===state.page)?.[2]||'Panoramica';document.querySelector('#darkBtn').classList.toggle('chosen',state.theme==='dark');document.querySelector('#lightBtn').classList.toggle('chosen',state.theme==='light');document.body.dataset.theme=state.theme}
function overview(){const running=state.updateRun==='running';return head('OPERATIONS','Control Center','La salute del sistema e le azioni importanti, senza scorrere tra venti moduli.',button('Apri aggiornamenti','goto-updates','primary'))+`<div class="grid cols4">${stat('Core MCP','Online','green','server','Healthcheck OK')}${stat('Native Host Agent','Connesso','green','activity','Socket systemd attivo')}${stat('MCP endpoint','Protetto','blue','lock','HTTPS · OAuth + API Token')}${stat('Versione installata',state.installed,'blue','update',running?'Aggiornamento in corso':'Release beta')}</div>`+section('Cosa richiede attenzione','Stato sintetico e prossime azioni')+`<div class="grid cols2">${card(`<div class="card-top"><div><h2>${ic('update',16)} Aggiornamenti</h2><p>Resta nella pagina: lo stato si aggiorna da solo.</p></div>${badge(running?'In corso':'Demo disponibile',running?'orange':'blue')}</div><div class="split"><div class="smalltext">Installata <strong>${esc(state.installed)}</strong><br>Prossima: ${esc(state.latest)} <span class="micro">(simulazione)</span></div>${button(running?'Segui avanzamento':'Gestisci','goto-updates','primary')}</div>${running?`<div class="bar" style="margin-top:15px"><i style="width:${progress()}%"></i></div>`:''}`)}${card(`<div class="card-top"><div><h2>${ic('shield',16)} Scope autorizzato</h2><p>Verifica i target consentiti prima di eseguire tool.</p></div>${badge(state.cfg.KALI_MCP_ALLOW_ALL_TARGETS==='true'?'Allow all + blacklist':'Allowlist','orange')}</div><div class="split"><span class="smalltext">Blacklist: <code>${esc(state.cfg.KALI_MCP_DENIED_CIDRS||'nessuna')}</code></span>${button('Modifica','goto-scope')}</div>`)}${card(`<div class="card-top"><div><h2>${ic('key',16)} Permessi sensibili</h2><p>I limiti del deployment sono separati dai toggle runtime.</p></div>${badge('Root OFF','green')}</div><div class="split"><span class="smalltext">Host Exec ${state.cfg.KALI_MCP_ALLOW_HOST_EXEC==='true'?'consentito':'bloccato'} · Host Root ${state.cfg.KALI_MCP_ALLOW_HOST_ROOT==='true'?'consentito':'bloccato'}</span>${button('Controlla','goto-permissions')}</div>`)}${card(`<div class="card-top"><div><h2>${ic('globe',16)} Client browser</h2><p>Origini CORS e credenziali sono autorizzazioni distinte.</p></div>${badge(`${state.origins.length} origine`,'blue')}</div><div class="split"><span class="smalltext">Token attivi: ${state.api.filter(x=>x.status==='Attivo').length} · OAuth: ${state.oauth.length}</span>${button('Gestisci','goto-clients')}</div>`)} </div>`+section('Attività recente','Alcuni eventi rappresentativi; non sono dati del tuo Raspberry',button('Apri audit','goto-logs'))+card(`<div class="rowlist">${state.events.slice(0,5).map(x=>`<div class="setting-row"><div class="grow"><div class="label">${esc(x.action)}</div><p>${esc(x.actor)} · ${esc(x.detail)}</p></div>${badge(x.status,x.status==='DENIED'?'red':'green')}</div>`).join('')}</div>`, 'flat')}
function stat(title,v,t,i,foot){return card(`<div class="card-top"><span class="statname">${esc(title)}</span><span class="symbol">${ic(i,17)}</span></div><div class="statbig" style="font-size:${v.length>19?'16':'23'}px">${esc(v)}</div><div class="statbottom">${badge(t==='green'?'Operativo':'Verificato',t)} &nbsp; ${esc(foot)}</div>`)}
function progress(){return state.updateRun==='success'?100:state.updateRun==='failed'?75:Math.max(0,(state.updateIndex+1)/steps.length*100)}
function updates(){const running=state.updateRun==='running',completed=state.updateRun==='success',failed=state.updateRun==='failed';return head('RELEASE MANAGEMENT','Aggiornamenti senza perdere il filo','Una sola timeline per download, installer systemd, riavvio e controllo finale. La vista rimane aggiornata automaticamente.',`${button('Verifica release','check-update','ghost',running?'disabled':'')}${button('Simula installazione','install','primary',running?'disabled':'')}`)+`<div class="grid cols3">${stat('Installata',state.installed,'green','server','Versione corrente')}${stat('Disponibile',state.latest,'blue','update','Solo demo; release non reale')}${stat('Stato installer',running?'In esecuzione':failed?'Fallito':completed?'Completato':'Pronto',failed?'red':completed?'green':'blue','clock','Workflow systemd · demo')}</div>${card(`<div class="card-top"><div><h2>Job di aggiornamento</h2><p>ID: <code>upgrade-staging-0007</code> · La pagina non va ricaricata</p></div>${badge(running?'Live':completed?'Completato':failed?'Fallito':'Non avviato',running?'orange':completed?'green':failed?'red':'blue')}</div><div class="split"><strong>${running?steps[state.updateIndex]||'Preparazione':completed?'Aggiornamento verificato':failed?'Installazione non riuscita':'Avvia una simulazione di installazione'}</strong><span class="muted">${Math.round(progress())}%</span></div><div class="bar" style="margin:11px 0 18px"><i style="width:${progress()}%"></i></div>${state.updateIndex===5&&running?`<div class="notice warn">${ic('wifi',16)}<span>Core temporaneamente non raggiungibile. La UI mantiene il job e prova automaticamente la riconnessione.</span></div>`:''}${failed?`<div class="notice error">${ic('alert',16)}<span>Healthcheck non riuscito. <strong>Configurazione precedente ripristinata (simulato).</strong> Nessun JSON grezzo: apri dettagli e riprova.</span></div>`:''}<ol class="timeline">${steps.map((x,i)=>`<li class="${completed?'done':failed&&i===6?'failed':state.updateIndex>i?'done':state.updateIndex===i?'active':''}"><span class="stepdot">${state.updateIndex>i||completed?'✓':i+1}</span><span>${esc(x)}</span><small>${state.updateIndex>i||completed?'OK':failed&&i===6?'Errore':state.updateIndex===i&&running?'In corso':'In attesa'}</small></li>`).join('')}</ol><div class="actionrow"><div class="pillgroup">${badge('Monitoraggio automatico · demo','blue')}<span class="micro">Refresh UI ogni 1,4 s</span></div>${button('Simula errore al prossimo tentativo','fail-next','ghost')}${failed?button('Riprova','install','primary'):''}</div>`, 'flat')+`<div class="notice">${ic('info',17)}<span><strong>Produzione:</strong> servono uno stato persistente dell'installer systemd e una riconnessione automatica dopo il riavvio. La beta.11 attuale espone job di scheduling, non tutta questa timeline. Qui è una simulazione di UX.</span></div>`+section('Impostazioni aggiornamenti')+card(`<div class="fields"><label class="field"><span>Canale release</span><select data-config="KALI_MCP_RELEASE_CHANNEL"><option value="beta" ${state.cfg.KALI_MCP_RELEASE_CHANNEL==='beta'?'selected':''}>Beta</option><option value="stable" ${state.cfg.KALI_MCP_RELEASE_CHANNEL==='stable'?'selected':''}>Stable</option></select><small>KALI_MCP_RELEASE_CHANNEL</small></label><label class="field"><span>Intervallo controlli (secondi)</span><input class="textinput" type="number" min="900" max="86400" data-config="KALI_MCP_UPDATE_CHECK_SECONDS" value="${esc(state.cfg.KALI_MCP_UPDATE_CHECK_SECONDS)}"><small>KALI_MCP_UPDATE_CHECK_SECONDS</small></label></div>${button('Applica impostazioni','apply-config','primary')}`)}
function scope(){const allow=state.mode==='all';return head('SECURITY / ENGAGEMENT','Authorized Scope','Le esclusioni CIDR prevalgono su allowlist e Allow all. Cambiare scope è una modifica amministrativa ad alto impatto.',button('Testa un target','scope-focus','ghost'))+`<div class="grid cols2"><div class="stack">${card(`<div class="card-top"><div><h2>Modalità di autorizzazione</h2><p>Seleziona il criterio che Kali MCP applicherà agli adapter tipizzati.</p></div>${badge(allow?'Ampio · richiede conferma':'Ristretto',allow?'orange':'green')}</div><div class="radio-cards"><button class="mode ${allow?'':'active'}" data-action="mode" data-value="allowlist"><span>${ic('shield',17)} Solo allowlist</span><small>Autorizza unicamente gli IP dichiarati</small></button><button class="mode ${allow?'active':''}" data-action="mode" data-value="all"><span>${ic('globe',17)} Allow all − blacklist</span><small>Autorizza tutti tranne gli esclusi</small></button></div><div class="separator"></div><div class="stack"><label class="field"><span>Reti consentite</span><textarea id="allowedCidrs" spellcheck="false">${esc(state.draftAllowed)}</textarea><small>KALI_MCP_ALLOWED_CIDRS · uno o più CIDR separati da virgola</small></label><label class="field"><span>Blacklist — sempre esclusi</span><textarea id="deniedCidrs" spellcheck="false">${esc(state.draftDenied)}</textarea><small>KALI_MCP_DENIED_CIDRS · precedenza assoluta</small></label>${allow?`<label class="field"><span>Conferma digitando ALLOW ALL</span><input id="allowConfirm" class="textinput" autocomplete="off" placeholder="ALLOW ALL"></label>`:''}</div><div class="notice warn">${ic('alert',16)}<span>Lo scope degli adapter <strong>non equivale a un firewall</strong>. Le shell host generiche richiedono un controllo di rete separato.</span></div><div class="actionrow"><span class="smalltext">Modifica protetta da password superuser lato backend</span>${button('Applica e verifica','save-scope','primary')}</div>`)} </div><div class="stack">${card(`<div class="card-top"><div><h2>Simulatore di policy IP</h2><p>Prova un indirizzo prima di applicare lo scope.</p></div>${badge('Anteprima locale IPv4','blue')}</div><label class="field"><span>Target da verificare</span><input id="probeIP" class="textinput mono" value="${esc(state.testIP)}" placeholder="192.168.0.1"></label><div id="probeResult">${scopeResult(state.testIP)}</div><div class="actionrow">${button('192.168.0.1','probe-one')}${button('192.168.137.42','probe-denied')}</div>`)}${card(`<h2>Ordine di valutazione</h2><div class="rowlist"><div class="setting-row"><span class="number">1</span><div><strong>Blacklist</strong><p>Se il target è escluso, nega sempre.</p></div></div><div class="setting-row"><span class="number">2</span><div><strong>Allow all</strong><p>Se attivo, ammetti ogni altro IP.</p></div></div><div class="setting-row"><span class="number">3</span><div><strong>Allowlist</strong><p>Se non è Allow all, consenti solo reti esplicite.</p></div></div></div>`)} </div></div>`}
function cidrMatch(ip,list){if(!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip))return null;let oct=ip.split('.').map(Number);if(oct.some(x=>x>255))return null;const n=oct.reduce((a,b)=>((a<<8)>>>0)+b,0)>>>0;return String(list||'').split(/[\n, ]+/).some(t=>{if(!t)return false;let [base,mask]=t.trim().split('/');if(!/^\d{1,3}(\.\d{1,3}){3}$/.test(base))return false;let arr=base.split('.').map(Number);if(arr.some(v=>v>255))return false;let bits=mask===undefined?32:Number(mask);if(!Number.isInteger(bits)||bits<0||bits>32)return false;let b=arr.reduce((a,v)=>((a<<8)>>>0)+v,0)>>>0;let m=bits===0?0:(0xffffffff<<(32-bits))>>>0;return (n&m)===(b&m)})}
function scopeResult(ip){let result='Target non valido',type='orange',reason='Inserisci un IPv4 valido per il simulatore.';let blocked=cidrMatch(ip,state.draftDenied),allowed=cidrMatch(ip,state.draftAllowed);if(blocked!==null){if(blocked){result='Negato',type='red',reason='Rientra nella blacklist. Ha precedenza anche su Allow all.'}else if(state.mode==='all'){result='Consentito (mock)',type='green',reason='Allow all è attivo e il target non è escluso.'}else if(allowed){result='Consentito (mock)',type='green',reason='Il target appartiene alla allowlist.'}else{result='Negato',type='red',reason='Non appartiene alla allowlist.'}}return `<div class="notice ${type==='red'?'error':type==='green'?'success':'warn'}">${ic(type==='red'?'alert':'shield',17)}<div><strong>${esc(result)}</strong><div class="smalltext">${esc(reason)}</div></div></div>`}
function permissions(){return head('SECURITY / CAPABILITIES','Permessi e privilegi','Due livelli separati: il deployment definisce il limite massimo; i toggle runtime consentono l’uso effettivo.')+`<div class="grid cols2">${card(`<div class="card-top"><div><h2>Abilitazioni runtime</h2><p>La disponibilità dipende dal limite imposto dal deployment.</p></div>${badge('Conferma per azioni critiche','orange')}</div><div class="rowlist">${runtime.map(([id,name,desc,env])=>{const ceiling=state.cfg[env]==='true',value=state.runtime[id];return `<div class="setting-row"><div class="grow"><div class="label">${esc(name)}</div><p>${esc(desc)}</p><code>${esc(env)}: ${ceiling?'true':'false'}</code></div>${!ceiling?badge('Bloccato dal ceiling','orange'):badge(value?'Enabled':'Disabled',value?'green':'blue')}<button aria-label="${esc(name)}" class="toggle ${value?'on':''}" data-action="runtime" data-value="${id}" ${ceiling?'':'disabled'}><i></i></button></div>`}).join('')}</div>`)}${card(`<div class="card-top"><div><h2>Deployment ceilings</h2><p>Modifiche persistenti su Core e Agent, con verifica e rollback.</p></div>${badge('Root = rischio elevato','orange')}</div><div class="rowlist">${configs.filter(x=>x[1]==='Permessi').map(([key,group,type,def,desc])=>`<div class="setting-row"><div class="grow"><div class="label">${esc(key.replace('KALI_MCP_ALLOW_','').replaceAll('_',' '))}</div><p>${esc(desc)}</p><code>${esc(key)}</code></div><button aria-label="Cambia ${esc(key)}" class="toggle ${state.cfg[key]==='true'?'on':''}" data-action="ceiling" data-value="${key}"><i></i></button></div>`).join('')}</div>`)} </div><div class="notice">${ic('info',16)}<span>I limiti di deployment e i permessi runtime sono indipendenti. Ogni modifica richiede la password del superuser e viene verificata lato server.</span></div>`}
function clients(){return head('IDENTITY & ACCESS','Client MCP e token','Gestisci API Bearer e OAuth separatamente. Una permissione CORS non crea una credenziale.',button('Nuovo token','new-token','primary'))+`${section('API Token','Valore segreto visibile una sola volta alla creazione')}${card(`<div class="tablewrap"><table><thead><tr><th>Client</th><th>Token ID</th><th>Scadenza</th><th>Stato</th><th>Azioni</th></tr></thead><tbody>${state.api.map((t,i)=>`<tr><td><strong>${esc(t.name)}</strong></td><td><code>${esc(t.id)}</code></td><td>${esc(t.expires)}</td><td>${badge(t.status,t.status==='Attivo'?'green':'red')}</td><td>${button('Ruota','rotate-token','small',`data-index="${i}" ${t.status!=='Attivo'?'disabled':''}`)} ${button('Revoca','revoke-token','small danger',`data-index="${i}" ${t.status!=='Attivo'?'disabled':''}`)}</td></tr>`).join('')}</tbody></table></div>${state.tokenReveal?`<div class="notice success">${ic('key',17)}<div><strong>Token reale — mostrato una sola volta</strong><div class="token-pill">${esc(state.tokenReveal)}</div><p>Conservalo subito in un password manager: il valore non potrà essere recuperato.</p></div></div>`:''}`)}${section('Client OAuth / PKCE','L’accesso può essere revocato senza toccare gli altri client')}${card(`<div class="tablewrap"><table><thead><tr><th>Client</th><th>Client ID</th><th>Stato</th><th>Azioni</th></tr></thead><tbody>${state.oauth.map((t,i)=>`<tr><td><strong>${esc(t.name)}</strong></td><td><code>${esc(t.id)}</code></td><td>${badge(t.status,t.status==='Attivo'?'green':'red')}</td><td>${button('Revoca','revoke-oauth','small danger',`data-index="${i}" ${t.status!=='Attivo'?'disabled':''}`)}</td></tr>`).join('')}</tbody></table></div>`)}${section('Autenticazione')}${card(`<div class="setting-row"><div class="grow"><div class="label">API Bearer Authentication</div><p>In aggiunta al flusso OAuth PKCE. Non sostituisce CORS.</p><code>KALI_MCP_API_HEADER_ENABLED</code></div><button class="toggle ${state.cfg.KALI_MCP_API_HEADER_ENABLED==='true'?'on':''}" data-action="ceiling" data-value="KALI_MCP_API_HEADER_ENABLED"><i></i></button></div>`)} `}
function cors(){return head('BROWSER ACCESS','Origini CORS e diagnostica','Autorizzazione esatta dell’origine HTTPS, separata dai token. Nessun wildcard.',button('Aggiungi origine','focus-origin','primary'))+`<div class="grid cols2">${card(`<div class="card-top"><div><h2>Origini attive nel Core</h2><p>Visualizza il valore salvato e applicato al servizio.</p></div>${badge(`${state.origins.length} consentita/e`,'green')}</div><div class="rowlist">${state.origins.map((o,i)=>`<div class="setting-row"><div class="grow"><div class="label mono">${esc(o)}</div><p>HTTPS · origin esatta</p></div>${button('Rimuovi','remove-origin','small danger',`data-index="${i}"`)}</div>`).join('')||'<div class="empty">Nessuna origine aggiunta.</div>'}</div><label class="field" style="margin-top:16px"><span>Nuova origine browser</span><input id="originField" class="textinput" placeholder="https://llm.example.com" autocomplete="off"><small>Niente path, wildcard o Origin: null. La password superuser viene richiesta dal backend.</small></label><div class="actionrow">${button('Autorizza origine','add-origin','primary')}</div>`)}${card(`<div class="card-top"><div><h2>Test collegamento MCP</h2><p>Una verifica OPTIONS 204 da sola non prova initialize/tools/list.</p></div>${badge('Test reale','blue')}</div><label class="field"><span>Origin da testare</span><select id="corsProbe"><option value="">Seleziona un’origine</option>${state.origins.map(o=>`<option value="${esc(o)}">${esc(o)}</option>`).join('')}</select></label><div class="notice">${ic('lock',16)}<span>OPTIONS CORS è testabile senza credenziali. Per verificare initialize e tools/list usa un token Bearer valido, mai salvato.</span></div><div class="actionrow"><label class="field"><span>Bearer API token (facoltativo)</span><input id="corsBearer" class="textinput" type="password" maxlength="512" autocomplete="off" placeholder="Necessario per initialize / tools/list"></label>${button('Esegui test','test-cors','primary')}</div><div id="corsResult"></div>`)} </div>`}
function files(){return head('TRANSFERS & EXECUTION','File, trasferimenti e job','OpenLink e Base64 a blocchi fino a 100 MB per file; qui vengono simulati soltanto nome e dimensione.',button('Simula upload','focus-file','primary'))+`<div class="grid cols3">${stat('File massimo','100 MB','blue','file','OpenLink / Base64 chunk')}${stat('Quota per client','300 MB','blue','folder','16 file massimo')}${stat('Job timeout',state.cfg.KALI_MCP_MAX_JOB_SECONDS+' s','blue','clock','KALI_MCP_MAX_JOB_SECONDS')}</div>${section('Trasferisci un file')}${card(`<div class="fields"><label class="field"><span>Metodo</span><select id="fileMode"><option value="openlink">OpenLink · HTTP PUT/GET</option><option value="base64">Base64 a blocchi · 128 KiB</option></select><small>OpenLink: URL monouso 10 min. Base64: più chiamate MCP.</small></label><label class="field"><span>Seleziona un file locale (solo metadati)</span><input id="demoFile" type="file" class="textinput"><small>Il contenuto non viene letto o caricato da questa simulazione.</small></label></div><div class="actionrow">${button('Simula upload','upload','primary')}</div><div class="notice">${ic('info',16)}<span>Il file rimane sul tuo dispositivo. La staging non contatta il server MCP, non invia dati e non conserva file.</span></div>`)}${section('File recenti')}${card(`<div class="tablewrap"><table><thead><tr><th>Nome</th><th>Dimensione</th><th>Metodo</th><th>Stato</th></tr></thead><tbody>${state.files.map(x=>`<tr><td><strong>${esc(x.name)}</strong></td><td>${(x.size/1024).toFixed(1)} KiB</td><td>${esc(x.mode)}</td><td>${badge(x.status,'green')}</td></tr>`).join('')}</tbody></table></div>`)}${section('Job MCP','La cronologia dei job usa dettagli e polling dedicati')}${jobTable()}${card(`<div class="fields"><label class="field"><span>Timeout massimo job (secondi)</span><input class="textinput" type="number" min="5" max="3600" data-config="KALI_MCP_MAX_JOB_SECONDS" value="${esc(state.cfg.KALI_MCP_MAX_JOB_SECONDS)}"><small>KALI_MCP_MAX_JOB_SECONDS</small></label></div>${button('Salva timeout','apply-config','primary')}`)} `}
function jobTable(){return card(`<div class="tablewrap"><table><thead><tr><th>Job</th><th>Client</th><th>Orario</th><th>Stato</th><th>Dettagli</th></tr></thead><tbody>${(state.updateRun==='running'||state.updateRun==='success'||state.updateRun==='failed'?[{id:'upgrade-staging-0007',tool:'core-upgrade',actor:'webui',time:'Ora',state:state.updateRun==='running'?'In corso':state.updateRun==='success'?'Completato':'Fallito'}]:[]).concat(sampleJobs).map(j=>`<tr><td><strong>${esc(j.tool)}</strong><div class="micro mono">${esc(j.id)}</div></td><td>${esc(j.actor)}</td><td>${esc(j.time)}</td><td>${badge(j.state,j.state==='Completato'?'green':j.state==='Bloccato'||j.state==='Fallito'?'red':'orange')}</td><td>${button('Apri','job-detail','small',`data-job="${esc(j.id)}"`)}</td></tr>`).join('')}</tbody></table></div>`)}
function logs(){return head('AUDIT & TELEMETRY','Audit e attività','Eventi reali registrati con autore, azione ed esito. I dati si aggiornano automaticamente.',button('Guida errori','error-demo','ghost'))+`<div class="grid cols2">${jobTable()}${card(`<div class="card-top"><div><h2>Audit recente</h2><p>Eventi etichettati, con autore e risultato.</p></div>${badge(`${state.events.length} eventi`,'blue')}</div>${state.events.map(x=>`<div class="auditline"><span>${esc(x.at)}</span><span>${esc(x.actor)}</span><div><strong>${esc(x.action)}</strong><div class="micro">${esc(x.detail)}</div></div>${badge(x.status,x.status==='DENIED'?'red':'green')}</div>`).join('')}`)} </div>`}
function settings(){let matches=configs.filter(x=>[x[0],x[1],x[4]].join(' ').toLowerCase().includes(state.search.toLowerCase()));return head('CONFIGURATION INVENTORY','Tutte le variabili','Inventario reale del deployment. Cerca una variabile e applica modifiche con password superuser.')+card(`<div class="split"><div class="grow"><label class="field"><span>Cerca nelle variabili configurabili</span><input id="settingSearch" class="textinput" value="${esc(state.search)}" placeholder="Es. CIDRS, ROOT, PORT, UPDATES" autofocus></label></div>${badge(`${matches.length}/17 variabili`,'blue')}</div><div class="tablewrap" style="margin-top:15px"><table><thead><tr><th>Variabile</th><th>Gruppo</th><th>Valore attuale</th><th>Azione</th></tr></thead><tbody>${matches.map(([key,group,type,defaultV,desc])=>`<tr><td><strong class="mono">${esc(key)}</strong><div class="micro">${esc(desc)}</div></td><td>${badge(group,'blue')}</td><td><code>${esc(state.cfg[key]||'(vuoto)')}</code></td><td>${button('Modifica','edit-setting','small',`data-key="${key}"`)}</td></tr>`).join('')}</tbody></table></div>`)+section('Installer-managed e credenziali','Visibili come voci, ma non modificabili liberamente')+card(`<div class="tablewrap"><table><thead><tr><th>Variabile</th><th>Valore</th><th>Motivo</th></tr></thead><tbody>${internal.map(k=>`<tr><td><code>${esc(k)}</code></td><td>${k.includes('PASSWORD')||k.includes('FILE')?'(nascosto)':'(gestita dall’installer)'}</td><td class="muted">${k.includes('PASSWORD')||k.includes('SUPERUSER')?'Credenziali gestite da un flusso protetto':k.includes('SOCKET')||k.includes('GID')||k.includes('GROUP')?'Socket/identità del Native Host Agent':'Infrastruttura e topologia protetta'}</td></tr>`).join('')}</tbody></table></div>`)}
function lab(){const done=Object.values(state.tests).filter(Boolean).length;return head('UX VALIDATION','Laboratorio test UX','Quattro scenari realistici per valutare comprensibilità e tempi di completamento. Nessuna interazione con l’istanza reale.',button('Ripristina simulazione','reset-demo'))+`${card(`<div class="split"><div><h2>Prova i flussi come un amministratore</h2><p>Passi compiuti in questa sessione di staging: <strong>${done}/4</strong>. Non sono test con utenti reali.</p></div>${badge(`${done*25}% completati`,done===4?'green':'blue')}</div><div class="bar" style="margin-top:12px"><i style="width:${done*25}%"></i></div>`,'highlight')}${section('Scenari guidati','Clicca “Prova scenario”, completa il flusso e torna qui')}${['update','scope','cors','settings'].map((id,i)=>{let titles=['Aggiorna senza perdere lo stato','Escludi una subnet dallo scope','Autorizza una WebUI MCP','Trova un setting per nome'];let descriptions=['Avvia un update simulato, osserva riavvio e healthcheck, senza refresh.','Configura la blacklist, testa un IP escluso e salva con conferma.','Aggiungi origine HTTPS e verifica la connessione MCP simulata.','Cerca KALI_MCP_PORT e modifica il valore in sicurezza.'];let routes=['updates','scope','cors','settings'];return `<div class="testcard" style="margin:9px 0"><span class="number">${i+1}</span><div class="grow"><strong>${titles[i]}</strong><div class="smalltext">${descriptions[i]}</div></div>${badge(state.tests[id]?'Completato':'Da provare',state.tests[id]?'green':'blue')} ${button('Prova','scenario','small',`data-value="${routes[i]}"`)}</div>`}).join('')}${section('Confronta due linguaggi visivi','La struttura delle schermate resta uguale; valuta contrasto, leggibilità e densità')}${card(`<div class="split"><div><strong>Console scura</strong><p>Per sessioni lunghe, monitoraggio e log.</p></div>${button('Attiva Console','theme','small',`data-value="dark"`)}</div><div class="separator"></div><div class="split"><div><strong>Light professionale</strong><p>Per configurazione, moduli e tabelle amministrative.</p></div>${button('Attiva Light','theme','small',`data-value="light"`)}</div>`)} `}
const views={overview,updates,scope,permissions,clients,cors,files,logs,settings,lab};
function render(){side();const target=document.getElementById('content');target.innerHTML=(views[state.page]||overview)();document.getElementById('side').classList.remove('open')}
function goto(page){state.page=page;render();window.scrollTo({top:0,behavior:'instant'})}
function toast(msg,type='good'){const el=document.createElement('div');el.className='toast '+type;el.innerHTML=ic(type==='bad'?'alert':'check',17)+'<span>'+esc(msg)+'</span>';const box=document.getElementById('toasts');box.appendChild(el);setTimeout(()=>el.remove(),5300)}
function modal(title,body,yes,action,onYes){document.getElementById('overlay').innerHTML=`<div class="modalcover"><div class="modal" role="dialog" aria-modal="true" aria-label="${esc(title)}"><h2>${esc(title)}</h2><p>${body}</p><div class="modal-foot">${button('Annulla','modal-cancel')}${button(yes,action,'primary')}</div></div></div>`;window.pendingConfirm=onYes;setTimeout(()=>document.querySelector('#overlay .btn.primary')?.focus(),0)}
function closeModal(){document.getElementById('overlay').innerHTML='';window.pendingConfirm=null}
function applyValue(key,val){if(key==='KALI_MCP_PORT'&&(!/^\d+$/.test(val)||+val<1024||+val>65535))return toast('Porta non valida: usa 1024–65535.','bad');if(key==='KALI_MCP_UPDATE_CHECK_SECONDS'&&(+val<900||+val>86400))return toast('Intervallo: da 900 a 86400 secondi.','bad');if(key==='KALI_MCP_MAX_JOB_SECONDS'&&(+val<5||+val>3600))return toast('Timeout: da 5 a 3600 secondi.','bad');if(key==='KALI_MCP_PUBLIC_URL'&&!/^https:\/\/[^/\s]+$/.test(val))return toast('Indirizzo pubblico: origin HTTPS senza percorso.','bad');state.cfg[key]=String(val);log('superuser','deployment.update',key);toast('Impostazione salvata nella simulazione. Nessun servizio riavviato.');render();if(key.includes('PORT')||key.includes('BIND')||key==='KALI_MCP_PUBLIC_URL')toast('In produzione: questa modifica richiede verifica del tunnel e rollback.','bad')}
function confirmEdit(key){let data=configs.find(x=>x[0]===key);if(!data)return;let old=state.cfg[key],valueInput=data[2]==='bool'?`<select id="editVal"><option value="false" ${old==='false'?'selected':''}>false</option><option value="true" ${old==='true'?'selected':''}>true</option></select>`:`<input class="textinput" id="editVal" value="${esc(old)}">`;document.getElementById('overlay').innerHTML=`<div class="modalcover"><div class="modal" role="dialog" aria-modal="true"><h2>${esc(data[0])}</h2><p>${esc(data[4])}</p><label class="field"><span>Nuovo valore (staging)</span>${valueInput}</label><div class="notice">${ic('lock',16)}<span>Demo: in produzione richiede verifica del superuser e applicazione/rollback tramite Native Host Agent.</span></div><div class="modal-foot">${button('Annulla','modal-cancel')}${button('Simula applicazione','edit-confirm','primary',`data-key="${key}"`)}</div></div></div>`;setTimeout(()=>document.getElementById('editVal')?.focus(),0)}
function startUpdate(){if(state.updateRun==='running')return;if(state.updateRun==='success')state.installed='v0.1.0-beta.11';state.updateIndex=0;state.updateRun='running';log('webui','update.scheduled',state.latest);toast('Job schedulato. L’avanzamento si aggiorna automaticamente.');state.tests.update=true;render()}
let ticker=null;function tick(){if(state.updateRun!=='running')return;state.updateIndex++;if(state.updateIndex===5)toast('Core in riavvio: riconnessione automatica attiva.','bad');if(state.updateIndex>=6&&state.failNext){state.updateRun='failed';state.failNext=false;log('systemd','update.rollback','Healthcheck fallito. Ripristino simulato.','DENIED');toast('Update fallito: rollback simulato. Controlla il dettaglio.','bad')}else if(state.updateIndex>=steps.length){state.updateRun='success';state.updateIndex=steps.length;state.installed=state.latest;log('systemd','update.complete',state.installed);toast('Healthcheck OK. Installazione simulata completata.')}if(['updates','overview','files'].includes(state.page))render();else side()}
/* The production updater reads persisted systemd state, never advances fictitious timers. */
function saveScope(){state.draftAllowed=document.getElementById('allowedCidrs')?.value??state.draftAllowed;state.draftDenied=document.getElementById('deniedCidrs')?.value??state.draftDenied;const items=v=>v.split(/[\n,]+/).map(s=>s.trim()).filter(Boolean);if(state.mode==='all'&&!items(state.draftDenied).length)return toast('Allow all richiede almeno una subnet esclusa.','bad');if(state.mode==='all'&&document.getElementById('allowConfirm')?.value!=='ALLOW ALL')return toast('Scrivi esattamente ALLOW ALL per confermare.','bad');if(state.mode==='allowlist'&&items(state.draftAllowed).some(s=>s==='0.0.0.0/0'||s==='::/0'))return toast('Per un perimetro generale usa Allow all con blacklist.','bad');modal('Conferma modifica scope',`In produzione verrà richiesta di nuovo la <strong>password del superuser</strong>, verificata sul Native Host Agent. Qui non inserire password reali.`, 'Conferma simulata','modal-confirm',()=>{state.cfg.KALI_MCP_ALLOW_ALL_TARGETS=state.mode==='all'?'true':'false';state.cfg.KALI_MCP_ALLOWED_CIDRS=state.draftAllowed;state.cfg.KALI_MCP_DENIED_CIDRS=state.draftDenied;state.tests.scope=true;log('superuser','scope.update',state.mode+' / deny '+state.draftDenied);toast('Scope aggiornato nella simulazione.');render()})}
function addOrigin(){const value=document.getElementById('originField')?.value.trim()||'';if(!/^https:\/\/[a-z0-9.-]+(?::\d+)?$/i.test(value))return toast('Inserisci una origin HTTPS esatta, senza path o wildcard.','bad');if(state.origins.includes(value))return toast('Questa origin è già autorizzata.','bad');modal('Autorizza origine',`Aggiungere <code>${esc(value)}</code> alla allowlist CORS del Core? La conferma del superuser viene simulata.`, 'Autorizza (demo)','modal-confirm',()=>{state.origins.push(value);state.tests.cors=true;log('superuser','cors.origin.add',value);toast('Origin aggiunta nella simulazione.');render()})}
function newToken(){document.getElementById('overlay').innerHTML=`<div class="modalcover"><div class="modal" role="dialog" aria-modal="true"><h2>Nuovo API Token — demo</h2><p>Il valore verrà mostrato una sola volta. Non inserire dati reali.</p><label class="field"><span>Nome client</span><input id="tokenName" class="textinput" value="Nuovo client demo"></label><label class="field" style="margin-top:12px"><span>Durata</span><select id="tokenDays"><option>30</option><option>7</option><option>90</option></select></label><div class="modal-foot">${button('Annulla','modal-cancel')}${button('Crea token demo','create-token','primary')}</div></div></div>`}

/* LIVE CONTROL CENTER — no demo mutations, real backend authorization only. */
const LIVE_ACTIONS = new Set(['check-update','install','fail-next','save-scope','ceiling',
  'runtime','new-token','create-token','rotate-token','revoke-token','revoke-oauth',
  'add-origin','remove-origin','test-cors','upload','job-detail','error-demo',
  'edit-setting','edit-confirm','apply-config','reset-demo','logout','live-submit',
  'live-create-token']);
const LIVE_PHASES = ['scheduled','preflight','download','verify','backup',
                     'configuration','dependencies','activation','healthcheck','completed'];
const CSRF = document.querySelector('meta[name="kali-csrf"]')?.content || '';
let livePending = null;
let liveRefreshTimer = null;
let lastSnapshot = null;
let liveJobId = null;
state.hasSnapshot = false;
state.scopeDirty = false;
state.coreOnline = false;
state.agentOnline = false;
state.jobs = [];
state.inventory = [];
state.api = [];
state.oauth = [];
state.origins = [];
state.files = [];
state.events = [];
state.tokenReveal = '';
state.installed = 'In caricamento';
state.latest = 'In caricamento';
state.updateRun = 'idle';
state.updateIndex = -1;
state.updatePhase = 'scheduled';
state.runDetails = '';
state.allowInstall = false;
state.updateGuidance = '';
state.updateError = '';
state.updatedAt = null;
state.serverError = '';

function liveBadge(value, category) { return badge(String(value), category || 'blue'); }
function liveOverview() {
 const updating = ['scheduled','running'].includes(state.updateRun);
 const health = state.agentOnline ? 'Connesso' : 'Non disponibile';
 const rows = state.events.slice(0,5).map(x =>
   '<div class="setting-row"><div class="grow"><div class="label">'+esc(x.action)+'</div><p>'+
   esc(x.actor)+' · '+esc(x.detail || '—')+'</p></div>'+
   liveBadge(x.status, x.status==='DENIED'?'red':'green')+'</div>').join('');
 return head('OPERATIONS','Control Center','Stato reale dell’istanza e accesso immediato alle operazioni.',
   button('Gestisci aggiornamenti','goto-updates','primary'))+
   '<div class="grid cols4">'+
   stat('Core MCP','Online','green','server','Endpoint autenticato')+
   stat('Native Host Agent',health,state.agentOnline?'green':'red','activity','Socket systemd')+
   stat('MCP endpoint','Protetto','blue','lock','OAuth 2.0 · API Bearer')+
   stat('Versione installata',state.installed,'blue','update','Versione dal Core')+
   '</div>'+section('Da controllare','Stato aggiornato automaticamente')+
   '<div class="grid cols2">'+
   card('<div class="card-top"><div><h2>'+ic('update',16)+' Aggiornamenti</h2><p>Stato installer persistente sul Native Agent.</p></div>'+
     liveBadge(updating?'In corso':state.updateRun==='failed'?'Fallito':state.updateRun==='rolled_back'?'Rollback': 'Disponibile',
       updating?'orange':state.updateRun==='failed'?'red':'blue')+'</div>'+
     '<div class="split"><div class="smalltext">Installata <strong>'+esc(state.installed)+
     '</strong><br>GitHub: '+esc(state.latest)+'</div>'+button('Apri','goto-updates','primary')+'</div>'+
     (updating?'<div class="bar" style="margin-top:14px"><i style="width:'+
       Math.max(7,Math.round((state.updateIndex+1)/LIVE_PHASES.length*100))+'%"></i></div>':''))+
   card('<div class="card-top"><div><h2>'+ic('shield',16)+' Authorized Scope</h2><p>Blacklist prioritaria sugli adapter tipizzati.</p></div>'+
     liveBadge(state.cfg.KALI_MCP_ALLOW_ALL_TARGETS==='true'?'Allow all + blacklist':'Allowlist','orange')+
     '</div><div class="split"><span class="smalltext">Escluse: <code>'+
     esc(state.cfg.KALI_MCP_DENIED_CIDRS||'nessuna')+'</code></span>'+
     button('Gestisci','goto-scope')+'</div>')+
   card('<div class="card-top"><div><h2>'+ic('key',16)+' Permessi sensibili</h2><p>Ceilings e abilitazioni runtime separati.</p></div>'+
     liveBadge(state.runtime.host_root?'Root attivo':'Root disabilitato',
       state.runtime.host_root?'red':'green')+'</div><div class="split"><span class="smalltext">Host Exec '+
     (state.runtime.host_exec?'attivo':'disattivato')+'</span>'+
     button('Controlla','goto-permissions')+'</div>')+
   card('<div class="card-top"><div><h2>'+ic('globe',16)+' Client MCP</h2><p>OAuth, token e origini CORS distinte.</p></div>'+
     liveBadge(String(state.origins.length)+' origini','blue')+
     '</div><div class="split"><span class="smalltext">'+
     state.api.filter(x=>x.status==='Attivo').length+' token attivi · '+state.oauth.length+
     ' client OAuth</span>'+button('Gestisci','goto-clients')+'</div>')+
   '</div>'+section('Ultima attività','Audit reale')+
   card('<div class="rowlist">'+(rows||'<p class="muted">Nessun evento recente</p>')+'</div>','flat');
}

function liveUpdates(){
 const run=state.updateRun, running=['running','scheduled'].includes(run);
 const completed=run==='completed', failed=['failed','rolled_back'].includes(run);
 const current=LIVE_PHASES.indexOf(state.updatePhase);
 const idx=completed?LIVE_PHASES.length-1:Math.max(0,current);
 const status=completed?'Verificato':run==='rolled_back'?'Rollback':run==='failed'?'Errore':
   running?'Installer attivo': 'Nessun aggiornamento in corso';
 const percent=completed?100:Math.min(95,Math.round((idx+1)*100/LIVE_PHASES.length));
 const uiSteps=['Richiesta accettata','Preflight','Download release','Verifica release',
   'Backup','Configurazione','Dipendenze','Riavvio servizi','Healthcheck','Versione verificata'];
 const timeline=uiSteps.map((label,i)=>{
   const mode=completed?'done':failed&&idx===i?'failed':i<idx?'done':i===idx&&running?'active':'';
   return '<li class="'+mode+'"><span class="stepdot">'+(i<idx||completed?'✓':i+1)+
     '</span><span>'+esc(label)+'</span><small>'+
     (i<idx||completed?'OK':failed&&i===idx?'Fallito':i===idx&&running?'In corso':'In attesa')+
     '</small></li>';
 }).join('');
 const info=state.serverError?'<div class="notice warn">'+ic('wifi',16)+
   '<span>Core temporaneamente non raggiungibile. Riprovo automaticamente; '+
   'lo stato è conservato sul Native Agent.</span></div>':'';
 const fail=failed?'<div class="notice error">'+ic('alert',16)+'<span>'+
   esc(run==='rolled_back'?'La versione precedente è stata ripristinata.':
       'Installazione non confermata. Verifica il log root dell’installer.')+
   ' '+esc(state.runDetails)+'</span></div>':'';
 const action=button('Verifica release','check-update','ghost',running?'disabled':'')+
   button('Installa release disponibile','install','primary',
          running||!state.allowInstall?'disabled':'');
 return head('RELEASE MANAGEMENT','Aggiornamenti','Stato effettivo dell’installer systemd, anche dopo il riavvio del Core.',action)+
 '<div class="grid cols3">'+
 stat('Installata',state.installed,'green','server','Versione verificata')+
 stat('Disponibile',state.latest,'blue','update','Release del canale attivo')+
 stat('Stato installer',status,failed?'red':completed?'green':'blue','clock','Host Agent persistente')+
 '</div>'+section('Avanzamento installazione')+
 card('<div class="card-top"><div><h2>Installazione</h2><p>Fase attuale: '+
   esc(state.updatePhase)+' · Aggiornato: '+esc(state.updatedAt||'—')+
   '</p></div>'+liveBadge(status,failed?'red':completed?'green':running?'orange':'blue')+
   '</div><div class="split" role="status" aria-live="polite"><strong>'+
   esc(state.runDetails||status)+'</strong><span class="muted">'+
   (running?'Fase '+(idx+1)+'/'+LIVE_PHASES.length:status)+'</span></div>'+
   '<div class="bar" style="margin:11px 0 18px"><i style="width:'+
     (run==='idle'?0:percent)+'%"></i></div>'+info+fail+
   '<ol class="timeline">'+timeline+'</ol>'+
   '<div class="actionrow"><span class="smalltext">Sincronizzazione ogni 3 s · '+
   'La barra indica le fasi, non i byte scaricati.</span></div>','flat')+
 (state.updateGuidance?'<div class="notice">'+ic('info',16)+'<span>'+
   esc(state.updateGuidance)+'</span></div>':'')+
 section('Impostazioni aggiornamenti')+
 card('<div class="fields"><label class="field"><span>Canale release</span>'+
   '<select data-config="KALI_MCP_RELEASE_CHANNEL"><option value="beta"'+
   (state.cfg.KALI_MCP_RELEASE_CHANNEL==='beta'?' selected':'')+'>Beta</option>'+
   '<option value="stable"'+(state.cfg.KALI_MCP_RELEASE_CHANNEL==='stable'?' selected':'')+
   '>Stable</option></select><small>KALI_MCP_RELEASE_CHANNEL</small></label>'+
   '<label class="field"><span>Intervallo controlli (secondi)</span><input class="textinput"'+
   ' type="number" min="900" max="86400" data-config="KALI_MCP_UPDATE_CHECK_SECONDS" value="'+
   esc(state.cfg.KALI_MCP_UPDATE_CHECK_SECONDS||'21600')+
   '"><small>KALI_MCP_UPDATE_CHECK_SECONDS</small></label></div>'+
   '<div class="actionrow">'+button('Salva impostazioni','apply-config','primary')+'</div>');
}

function liveJobTable() {
 const rows=state.jobs.slice(0,60).map(j=>{
   const status=String(j.state||'unknown');
   return '<tr><td><strong>'+esc(j.tool_id||'job')+'</strong><div class="micro mono">'+
     esc(j.id.slice(0,16))+'</div></td><td>'+esc(j.actor||'—')+'</td><td>'+
     esc(j.created_at||j.started_at||'—')+'</td><td>'+
     liveBadge(status,status==='completed'?'green':status==='failed'?'red':'orange')+
     '</td><td>'+button('Apri','job-detail','small','data-job="'+esc(j.id)+'"')+
     '</td></tr>';
 }).join('');
 return card('<div class="tablewrap"><table><thead><tr><th>Tool</th><th>Client</th>'+
   '<th>Avvio</th><th>Stato</th><th>Dettagli</th></tr></thead><tbody>'+
   (rows||'<tr><td colspan="5">Nessun job registrato</td></tr>')+
   '</tbody></table></div>');
}

function liveFiles(){
 return head('TRANSFERS & EXECUTION','File, trasferimenti e job',
   'Trasferimenti MCP fino a 100 MB; job e audit aggiornati dal server.')+
   '<div class="grid cols3">'+
   stat('File massimo','100 MB','blue','file','OpenLink e Base64')+
   stat('Quota per client','300 MB','blue','folder','16 file contemporanei')+
   stat('Timeout job',(state.cfg.KALI_MCP_MAX_JOB_SECONDS||'300')+' s',
     'blue','clock','Massimo consentito')+'</div>'+
   section('Trasferimento file via MCP')+
   card('<div class="notice">'+ic('info',16)+
     '<span>OpenLink usa URL HTTPS firmati e monouso. Base64 usa blocchi da 128 KiB. '+
     'I file appartengono a ciascun client MCP: questa pagina amministrativa non '+
     'può accedere ai file di altri client.</span></div>'+
     '<p class="smalltext">Usa <code>files_upload</code>, <code>files_upload_chunk</code>, '+
     '<code>files_upload_finish</code>, <code>files_download</code>, '+
     '<code>files_list</code> e <code>files_delete</code> dal client MCP autenticato.</p>'+
     '<div class="actionrow"><a class="btn" href="/legacy">Apri strumenti legacy</a></div>')+
   section('Job MCP','Dati reali, seleziona un job per seguirne stato e output')+
   liveJobTable()+
   section('Timeout massimo job')+
   card('<label class="field"><span>Secondi</span><input type="number" '+
     'class="textinput" min="5" max="3600" data-config="KALI_MCP_MAX_JOB_SECONDS" value="'+
     esc(state.cfg.KALI_MCP_MAX_JOB_SECONDS||'300')+'"></label>'+
     '<div class="actionrow">'+button('Salva timeout','apply-config','primary')+'</div>');
}

function liveLogs(){
 const logs=state.events.map(x=>'<div class="auditline"><span>'+esc(x.at)+
   '</span><span>'+esc(x.actor)+'</span><div><strong>'+esc(x.action)+
   '</strong><div class="micro">'+esc(x.detail)+'</div></div>'+
   liveBadge(x.status,x.status==='DENIED'?'red':'green')+'</div>').join('');
 return head('AUDIT & TELEMETRY','Audit e attività',
   'Job e operazioni effettive, con esito e dettagli senza JSON grezzo.')+
   '<div class="grid cols2">'+liveJobTable()+
   card('<div class="card-top"><div><h2>Audit recente</h2><p>Ultime operazioni registrate.</p>'+
     '</div>'+liveBadge(state.events.length+' eventi','blue')+'</div>'+
     (logs||'<p class="muted">Nessun evento recente</p>'))+'</div>';
}

function liveSettings(){
 const matches=state.inventory.filter(x=>(x.name+' '+x.group+' '+x.description)
     .toLowerCase().includes(state.search.toLowerCase()));
 const editable=state.inventory.filter(x=>x.editable);
 const rows=matches.map(x=>'<tr><td><strong class="mono">'+esc(x.name)+
   '</strong><div class="micro">'+esc(x.description||'')+'</div></td><td>'+
   liveBadge(x.group,'blue')+'</td><td><code>'+esc(x.value||'(vuoto)')+
   '</code></td><td>'+ (x.editable?
      button('Modifica','edit-setting','small','data-key="'+esc(x.name)+'"'):
      '<span class="muted">Solo lettura</span>')+'</td></tr>').join('');
 return head('CONFIGURATION INVENTORY','Tutte le variabili',
   'Inventario del Native Agent; credenziali mascherate e chiavi interne protette.')+
   card('<div class="split"><div class="grow"><label class="field"><span>Cerca una variabile'+
      ' KALI_MCP_*</span><input id="settingSearch" class="textinput" value="'+esc(state.search)+
      '" placeholder="CIDRS, ROOT, PORT, UPDATE" autofocus></label></div>'+
      '<span id="settingsCount">'+liveBadge(matches.length+'/'+state.inventory.length+
      ' variabili','blue')+'</span></div>'+
      '<div class="tablewrap" style="margin-top:15px"><table><thead><tr><th>Variabile</th>'+
      '<th>Gruppo</th><th>Valore</th><th>Azione</th></tr></thead><tbody>'+
      (rows||'<tr><td colspan="4">Nessuna variabile corrispondente</td></tr>')+
      '</tbody></table></div>')+
   '<div class="notice">'+ic('lock',17)+'<span>'+editable.length+
      ' variabili modificabili con password superuser. Le altre sono gestite '+
      'dall’installer o tramite flussi dedicati; i segreti non sono visibili.</span></div>';
}

function liveGuide(){
 return head('DOCUMENTATION','Guida operativa',
   'Quattro flussi amministrativi e le relative protezioni.')+
   ['Aggiornamenti','Scope autorizzato','Client e token','Variabili e permessi'].map((x,i)=>
     card('<div class="setting-row"><span class="number">'+(i+1)+
       '</span><div class="grow"><div class="label">'+x+'</div><p>'+
       ['Verifica la release, conferma e segui il supervisore fino all’healthcheck reale.',
        'La blacklist prevale; la shell host generica non è protetta dal filtro CIDR degli adapter.',
        'Autorizza prima CORS, poi crea un token o OAuth e verifica la connessione.',
        'Controlla il ceiling, usa il toggle runtime e conferma con password superuser.'][i]+
       '</p></div>'+button('Apri','scenario','small','data-value="'+
       ['updates','scope','cors','settings'][i]+'")+'</div>')).join('')+
   section('Versione classica')+
   card('<p>La precedente dashboard rimane disponibile per diagnosi e rollback UX.</p>'+
        '<a href="/legacy" class="btn">Apri dashboard classica</a>');
}
views.overview=liveOverview; views.updates=liveUpdates; views.files=liveFiles;
views.logs=liveLogs; views.settings=liveSettings; views.lab=liveGuide;

function renderLoading(){
 document.getElementById('content').innerHTML=head('CONNESSIONE',
   'Caricamento Control Center','Connessione autenticata all’istanza Kali MCP…')+
   card('<p class="muted">Recupero status, configurazione, job e stato aggiornamenti.</p>');
}
function markConnection(online){
 const node=document.querySelector('.top .sync');
 if(!node)return;
 node.innerHTML='<span class="pulse"></span> '+(online?'DATI LIVE':'RICONNESSIONE');
 node.style.color=online?'var(--good)':'var(--warn)';
}
function applyLive(data){
 lastSnapshot=data; state.hasSnapshot=true; state.serverError='';
 state.coreOnline=true; state.agentOnline=Boolean(data.agent?.online);
 state.installed=String(data.updates?.installed||data.core?.version||'unknown');
 state.latest=String(data.updates?.latest||'Non verificata');
 state.allowInstall=data.updates?.install_allowed===true;
 state.updateGuidance=String(data.updates?.guidance||'');
 state.updateError=String(data.updates?.error||'');
 const run=data.updates?.run||{};
 state.updateRun=String(run.state||'idle');
 state.updatePhase=String(run.phase||'scheduled');
 state.updateIndex=LIVE_PHASES.indexOf(state.updatePhase);
 state.updatedAt=run.updated_at||null; state.runDetails=String(run.detail||'');
 state.cfg={};
 state.inventory=Array.isArray(data.fields)?data.fields:[];
 for(const item of state.inventory)if(item.editable)state.cfg[item.name]=String(item.value??'');
 state.runtime={};
 for(const id of runtime)state.runtime[id[0]]=Boolean(data.runtime?.[id[0]]?.enabled);
 if(!state.scopeDirty){
   state.mode=state.cfg.KALI_MCP_ALLOW_ALL_TARGETS==='true'?'all':'allowlist';
   state.draftAllowed=state.cfg.KALI_MCP_ALLOWED_CIDRS||'';
   state.draftDenied=state.cfg.KALI_MCP_DENIED_CIDRS||'';
 }
 state.origins=Array.isArray(data.origins?.configured)?data.origins.configured:[];
 state.activeOrigins=Array.isArray(data.origins?.active)?data.origins.active:[];
 state.api=Array.isArray(data.tokens)?data.tokens.map(x=>({...x,
   expires:x.expires?new Date(x.expires*1000).toLocaleDateString('it-IT'):'—'})):[];
 state.oauth=Array.isArray(data.oauth)?data.oauth:[];
 state.jobs=Array.isArray(data.jobs)?data.jobs:[];
 state.events=Array.isArray(data.audit)?data.audit.map(x=>({
   at:x.at||'',actor:x.actor||'',action:x.action||'',detail:x.detail||'',
   status:String(x.decision||'').toLowerCase()==='deny'?'DENIED':'OK'})):[];
 const tag=document.activeElement?.tagName;
 markConnection(true);
 if(!['INPUT','SELECT','TEXTAREA'].includes(tag) &&
     !document.getElementById('overlay').children.length)render();
 else side();
}
async function refreshLive(){
 try{
   const ctrl=new AbortController();
   const t=setTimeout(()=>ctrl.abort(),8000);
   let response;
   try {response=await fetch('/api/v1/ui/snapshot',{
       credentials:'same-origin',cache:'no-store',signal:ctrl.signal,
       headers:{Accept:'application/json'}});}
   finally{clearTimeout(t);}
   if(response.status===401){window.location.assign('/login?reason=session-expired&next=/');return;}
   if(!response.ok)throw new Error('HTTP '+response.status);
   const json=await response.json(); if(!json.ok)throw Error('Snapshot non disponibile');
   applyLive(json);
   if(liveJobId)await refreshJobDetails(liveJobId,false);
 }catch(err){
   state.serverError='Riconnessione: '+String(err.message||'server non raggiungibile');
   state.coreOnline=false;markConnection(false);
   if(!state.hasSnapshot)renderLoading();
 }
 clearTimeout(liveRefreshTimer);
 liveRefreshTimer=setTimeout(refreshLive,state.serverError?6000:3000);
}
function startLive(){
 const params=new URLSearchParams(location.search);
 const section=params.get('page');
 if(['overview','updates','scope','permissions','clients','cors','files','logs','settings','lab'].includes(section))
   state.page=section;
 liveJobId=/^[0-9a-f]{32}$/.test(params.get('job')||'')?params.get('job'):null;
 renderLoading();
 refreshLive();
}
function getFormError(source){
 const doc=new DOMParser().parseFromString(source,'text/html');
 const blocks=[...doc.querySelectorAll('h2,p')].map(n=>n.textContent.trim()).filter(Boolean);
 return (blocks.join(' — ')||'La richiesta è stata rifiutata').slice(0,380);
}
async function postLive(path, form){
 const fields=new URLSearchParams({...form,csrf:CSRF});
 try{
   const response=await fetch(path,{method:'POST',credentials:'same-origin',
     headers:{'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8',
              Accept:'text/html'},body:fields,redirect:'follow',cache:'no-store'});
   if(new URL(response.url).pathname==='/login'||response.status===401){
     window.location.assign('/login?reason=session-expired&next=/');
     return null;
   }
   const text=await response.text();
   if(!response.ok){
     const msg=getFormError(text);
     toast(msg,'bad');
     return null;
   }
   const htmlDoc=new DOMParser().parseFromString(text,'text/html');
   const token=htmlDoc.querySelector('textarea[readonly]');
   if(token && token.value.startsWith('kmp_')){
     state.tokenReveal=token.value;
     state.page='clients';
     toast('Token creato: copialo ora, non sarà recuperabile.');
   }else if(path.endsWith('/check') && path.includes('browser-origins')){
     const details=getFormError(text);
     toast(details.length>260?details.slice(0,260):details);
     const result=document.getElementById('corsResult');
     if(result)result.textContent=details;
   }else{
     toast('Richiesta accettata. Verifico lo stato reale del server.');
   }
   await refreshLive();
   return response;
 }catch(err){
   toast('Connessione interrotta. Verifica lo stato prima di riprovare: '+
     String(err.message||'server offline'),'bad');
   return null;
 }
}
function promptAdmin(title,description,action,phrase){
 livePending={action,phrase:phrase||''};
 document.getElementById('overlay').innerHTML='<div class="modalcover">'+
   '<div class="modal" role="dialog" aria-modal="true" aria-label="'+esc(title)+'">'+
   '<h2>'+esc(title)+'</h2><p>'+esc(description)+'</p>'+
   (phrase?'<label class="field"><span>Scrivi '+esc(phrase)+
      '</span><input class="textinput" id="liveConfirm" autocomplete="off" spellcheck="false"></label>':'')+
   '<label class="field" style="margin-top:12px"><span>Password superuser</span>'+
   '<input class="textinput" type="password" id="livePassword" autocomplete="current-password"></label>'+
   '<p class="micro">La password viene inviata soltanto al backend protetto. Nessuna azione '+
   'viene ripetuta automaticamente dopo un nuovo login.</p><div class="modal-foot">'+
   button('Annulla','modal-cancel')+button('Conferma','live-submit','primary')+
   '</div></div></div>';
 document.getElementById('livePassword')?.focus();
}
function liveAction(action,el){
 const value=el?.dataset.value;
 if(action==='live-submit'){
   if(!livePending)return;
   const password=document.getElementById('livePassword')?.value||'';
   const confirmation=document.getElementById('liveConfirm')?.value||'';
   if(!password)return toast('Inserisci la password del superuser.','bad');
   if(livePending.phrase && confirmation!==livePending.phrase)
     return toast('La conferma testuale non corrisponde.','bad');
   const done=livePending.action;
   livePending=null;closeModal();void done(password,confirmation);return;
 }
 if(action==='fail-next'||action==='reset-demo'||action==='upload'){
   return toast('Questa operazione di simulazione non è disponibile nella produzione.','bad');
 }
 if(action==='check-update')return void postLive('/api/v1/updates/check',{});
 if(action==='install'){
   if(!state.allowInstall)return toast(state.updateGuidance||'Installazione non autorizzata','bad');
   return modal('Conferma aggiornamento',
      'Installer systemd e Core verranno aggiornati davvero. Il servizio potrebbe riavviarsi. '+
      'La timeline leggerà lo stato persistente, senza confondere il job di scheduling con il completamento.',
      'Installa release','modal-confirm',
      ()=>{void postLive('/api/v1/updates/install',{confirm_update:'yes'});});
 }
 if(action==='save-scope'){
   state.draftAllowed=document.getElementById('allowedCidrs')?.value||'';
   state.draftDenied=document.getElementById('deniedCidrs')?.value||'';
   const allowed=state.draftAllowed.replace(/[\n;]+/g,',').trim();
   const denied=state.draftDenied.replace(/[\n;]+/g,',').trim();
   const all=state.mode==='all';
   if(all&&!denied)return toast('Allow all richiede una blacklist non vuota.','bad');
   if(all && document.getElementById('allowConfirm')?.value!=='ALLOW ALL')
     return toast('Inserisci ALLOW ALL nel campo di conferma.','bad');
   promptAdmin('Applica Authorized Scope',
     'Blacklist e allowlist vengono verificate dal Native Agent. La modifica riavvia il Core e mantiene un rollback.',
     async(password)=>{
       const answer=await postLive('/settings/deployment',{
         section:'scope',password,
         KALI_MCP_ALLOW_ALL_TARGETS:all?'true':'false',
         KALI_MCP_ALLOWED_CIDRS:allowed,
         KALI_MCP_DENIED_CIDRS:denied,confirm:all?'ALLOW ALL':''});
       if(answer)state.scopeDirty=false;
     });return;
 }
 if(action==='ceiling'){
   const key=value;
   const current=state.cfg[key]==='true';
   const target=current?'false':'true';
   return promptAdmin('Modifica limite di deployment',
     key+' → '+target+'. L’operazione riavvia il Core e il Native Agent.',
     password=>postLive('/settings/deployment',{
       section:'variable',key,value:target,password,
       confirm:key.includes('ROOT')&&target==='true'?'ENABLE ROOT':''}),
     key.includes('ROOT')&&target==='true'?'ENABLE ROOT':'');
 }
 if(action==='runtime'){
   const id=value, cap=runtime.find(x=>x[0]===id);
   if(!cap||state.cfg[cap[3]]!=='true')
     return toast('Il ceiling non consente questo permesso.','bad');
   const enabled=!state.runtime[id];
   return promptAdmin('Permesso runtime: '+id,
     'Conferma '+(enabled?'l’attivazione':'la disattivazione')+' del permesso.',
     password=>postLive('/api/v1/settings',{
       feature:id,enabled:enabled?'true':'false',superuser_password:password,
       disclaimer:id==='host_root'&&enabled?'yes':''}),
     id==='host_root'&&enabled?'ENABLE ROOT':'');
 }
 if(action==='new-token'){
   document.getElementById('overlay').innerHTML='<div class="modalcover"><div class="modal">'+
     '<h2>Nuovo API Token MCP</h2><label class="field">Nome client'+
     '<input class="textinput" id="liveTokenName" maxlength="80" required></label>'+
     '<label class="field">Durata (giorni)<input type="number" class="textinput" '+
     'id="liveTokenDays" value="30" min="1" max="90"></label>'+
     '<label class="field">Tool consentiti (opzionale, separati da virgola)'+
     '<input class="textinput" id="liveTokenTools" placeholder="system_status,tools_search"></label>'+
     '<label class="field">Origine CORS autorizzata (opzionale)'+
     '<input class="textinput" id="liveTokenOrigin" placeholder="https://llm.example.com"></label>'+
     '<label class="field">Password superuser'+
     '<input class="textinput" id="liveTokenPassword" type="password"></label>'+
     '<div class="modal-foot">'+button('Annulla','modal-cancel')+
     button('Crea token','live-create-token','primary')+'</div></div></div>';return;
 }
 if(action==='live-create-token'){
   const form={name:document.getElementById('liveTokenName')?.value||'',
     days:document.getElementById('liveTokenDays')?.value||'30',
     allowed_tools:document.getElementById('liveTokenTools')?.value||'',
     browser_origin:document.getElementById('liveTokenOrigin')?.value||'',
     password:document.getElementById('liveTokenPassword')?.value||''};
   if(!form.name||!form.password)return toast('Nome e password obbligatori.','bad');
   closeModal();return void postLive('/api/v1/api-tokens/create',form);
 }
 if(action==='revoke-token'||action==='rotate-token'){
   const token=state.api[Number(el?.dataset.index)];
   if(!token)return toast('Token non trovato.','bad');
   const rotating=action==='rotate-token';
   return promptAdmin((rotating?'Ruota':'Revoca')+' token API',
     token.name+' · La vecchia credenziale sarà revocata.',
     password=>postLive('/api/v1/api-tokens/'+(rotating?'rotate':'revoke'),{
       token_id:token.id,password, ...(rotating?{days:'30'}:{})}));
 }
 if(action==='revoke-oauth'){
   const client=state.oauth[Number(el?.dataset.index)];
   if(!client)return;
   return modal('Revoca client OAuth',client.name+' · Tutti i suoi token saranno revocati.',
     'Revoca','modal-confirm',()=>void postLive('/api/v1/clients/revoke',{client_id:client.id}));
 }
 if(action==='add-origin'){
   const origin=document.getElementById('originField')?.value.trim()||'';
   if(!/^https:\/\/[a-z0-9.-]+(?::\d+)?$/i.test(origin))
     return toast('Inserisci una origin HTTPS esatta senza path o wildcard.','bad');
   return promptAdmin('Autorizza origine CORS',origin,
     password=>postLive('/api/v1/browser-origins',{action:'add',origin,password}));
 }
 if(action==='remove-origin'){
   const origin=state.origins[Number(el?.dataset.index)];if(!origin)return;
   return promptAdmin('Rimuovi origine CORS',origin,
     password=>postLive('/api/v1/browser-origins',{action:'remove',origin,password}));
 }
 if(action==='test-cors'){
   const origin=document.getElementById('corsProbe')?.value||'';
   if(!origin)return toast('Seleziona una origine da verificare.','bad');
   return void postLive('/api/v1/browser-origins/check',{
     origin,bearer:document.getElementById('corsBearer')?.value||''});
 }
 if(action==='edit-setting'){
   const field=state.inventory.find(x=>x.name===el?.dataset.key&&x.editable);
   if(!field)return toast('Variabile gestita dall’installer o non modificabile.','bad');
   if(field.group==='Scope'){goto('scope');return;}
   const choice=field.type==='bool'?
     '<select class="textinput" id="liveSettingVal"><option value="false"'+
     (field.value==='false'?' selected':'')+'>false</option><option value="true"'+
     (field.value==='true'?' selected':'')+'>true</option></select>':
     '<input class="textinput" id="liveSettingVal" value="'+esc(field.value)+'">';
   document.getElementById('overlay').innerHTML='<div class="modalcover"><div class="modal">'+
     '<h2>'+esc(field.name)+'</h2><p>'+esc(field.description)+'</p>'+
     '<label class="field">Nuovo valore'+choice+'</label>'+
     '<label class="field">Conferma superuser<input class="textinput" '+
     'type="password" id="liveEditPassword"></label>'+
     (field.name.includes('ROOT')?
      '<label class="field">Conferma root<input class="textinput" id="liveEditConfirm" '+
      'placeholder="ENABLE ROOT"></label>':'')+
     '<div class="modal-foot">'+button('Annulla','modal-cancel')+
     button('Applica','edit-confirm','primary','data-key="'+esc(field.name)+'"')+
     '</div></div></div>';return;
 }
 if(action==='edit-confirm'){
   const key=el?.dataset.key, val=document.getElementById('liveSettingVal')?.value||'';
   const password=document.getElementById('liveEditPassword')?.value||'';
   const confirm=document.getElementById('liveEditConfirm')?.value||'';
   if(!password)return toast('Conferma password obbligatoria.','bad');
   if(key.includes('ROOT')&&val==='true'&&confirm!=='ENABLE ROOT')
     return toast('Scrivi ENABLE ROOT per abilitare root.','bad');
   closeModal();return void postLive('/settings/deployment',
     {section:'variable',key,value:val,password,confirm});
 }
 if(action==='apply-config'){
   const changes=[...document.querySelectorAll('[data-config]')].filter(x=>
     state.cfg[x.dataset.config]!==x.value).map(x=>[x.dataset.config,x.value]);
   if(!changes.length)return toast('Nessuna modifica da salvare.');
   if(changes.length>3)return toast('Massimo tre parametri per operazione.','bad');
   return promptAdmin('Applica configurazione',
     changes.map(x=>x[0]+' → '+x[1]).join(' · ')+
       '. Il Native Agent verificherà i valori e gestirà il riavvio.',
     password=>postLive('/settings/deployment',{
       section:'batch',changes:JSON.stringify(Object.fromEntries(changes)),password}));
 }
 if(action==='job-detail'){
   const id=el?.dataset.job;
   if(!/^[0-9a-f]{32}$/.test(id||''))return toast('ID job non valido.','bad');
   liveJobId=id;return void refreshJobDetails(id,true);
 }
 if(action==='error-demo')return goto('lab');
 if(action==='logout')return void postLive('/logout',{});
}
async function refreshJobDetails(id,open){
 try{
   const res=await fetch('/api/v1/jobs/'+encodeURIComponent(id),{
     credentials:'same-origin',cache:'no-store',headers:{Accept:'application/json'}});
   if(res.status===401){window.location.assign('/login');return;}
   if(!res.ok)throw Error('Job non trovato (HTTP '+res.status+')');
   const job=await res.json();if(job.error)throw Error(job.error);
   const outcome=job.result||{};
   const text=(outcome.stdout||outcome.stderr||outcome.error||'').slice(0,10000);
   const html='<h2>'+esc(job.tool_id||'Job')+'</h2>'+
     '<p>ID: <code>'+esc(job.id)+'</code></p>'+
     '<div class="notice">'+esc(job.state||'—')+' · '+esc(job.exit_code??'—')+'</div>'+
     '<pre style="max-height:340px;overflow:auto;white-space:pre-wrap">'+esc(text||'Nessun output disponibile')+'</pre>'+
     '<div class="modal-foot">'+button('Chiudi','modal-cancel')+'</div>';
   if(open||document.getElementById('overlay').dataset.jobId===id){
     document.getElementById('overlay').dataset.jobId=id;
     document.getElementById('overlay').innerHTML='<div class="modalcover"><div class="modal" '+
       'role="dialog" aria-modal="true">'+html+'</div></div>';
   }
 }catch(err){if(open)toast(String(err.message||err),'bad');}
}

function actionClick(a,el){if(LIVE_ACTIONS.has(a)){liveAction(a,el);return;}const v=el?.dataset.value;switch(a){case'nav':return goto(v);case'goto-updates':return goto('updates');case'goto-scope':return goto('scope');case'goto-permissions':return goto('permissions');case'goto-clients':return goto('clients');case'goto-logs':return goto('logs');case'mobile':document.getElementById('side').classList.toggle('open');return;case'theme':state.theme=v;render();return;case'help':return goto('lab');case'check-update':state.checked=true;log('webui','updates.check','Release demo disponibile');toast('Controllo simulato: release di esempio disponibile.');return;case'install':return modal('Avvia aggiornamento?','Questa è una <strong>simulazione</strong>. Il job rimarrà visibile durante riavvio e riconnessione, senza alcuna operazione sul Raspberry.','Avvia demo','modal-confirm',startUpdate);case'fail-next':state.failNext=true;return toast('Nel prossimo tentativo verrà simulato un healthcheck fallito.');case'mode':state.draftAllowed=document.getElementById('allowedCidrs')?.value??state.draftAllowed;state.draftDenied=document.getElementById('deniedCidrs')?.value??state.draftDenied;state.scopeDirty=true;state.mode=v;return render();case'probe-one':state.testIP='192.168.0.1';document.getElementById('probeIP').value=state.testIP;document.getElementById('probeResult').innerHTML=scopeResult(state.testIP);return;case'probe-denied':state.testIP='192.168.137.42';document.getElementById('probeIP').value=state.testIP;document.getElementById('probeResult').innerHTML=scopeResult(state.testIP);return;case'save-scope':return saveScope();case'scope-focus':document.getElementById('probeIP')?.focus();return;case'ceiling':{let key=v;let current=state.cfg[key]==='true';let risky=/ROOT|HOST_EXEC|NETWORK_CHANGES|PACKAGE_INSTALL/.test(key);return modal(risky?'Modifica di sicurezza critica':'Conferma impostazione',`<code>${esc(key)}</code><br>Nuovo valore: <strong>${current?'false':'true'}</strong>. Nella WebUI vera è obbligatoria la password superuser.`, 'Conferma simulata','modal-confirm',()=>applyValue(key,current?'false':'true'))}case'runtime':{let id=v,ceiling=runtime.find(x=>x[0]===id)?.[3];if(state.cfg[ceiling]!=='true')return toast('Prima devi autorizzare il limite di deployment.','bad');return modal('Modifica abilitazione runtime',`Stai per ${state.runtime[id]?'disabilitare':'abilitare'} <strong>${esc(id)}</strong> (demo).`, 'Conferma simulata','modal-confirm',()=>{state.runtime[id]=!state.runtime[id];log('superuser','capability.toggle',id);render()})}case'new-token':return newToken();case'create-token':{const name=document.getElementById('tokenName')?.value||'Demo';state.api.unshift({name,id:'tok_demo_'+Math.random().toString(36).slice(2,6),expires:'2026-12-08',status:'Attivo'});state.tokenReveal='kmp_demo_NOT_REAL_'+Math.random().toString(36).slice(2,17);log('superuser','token.create',name);closeModal();toast('Token demo creato e mostrato una sola volta.');return render()}case'revoke-token':{const i=+el.dataset.index;return modal('Revoca API Token',`Revocare <strong>${esc(state.api[i]?.name)}</strong>? Questa azione non si può annullare nella UI reale.`, 'Revoca (demo)','modal-confirm',()=>{state.api[i].status='Revocato';log('superuser','token.revoke',state.api[i].id);render()})}case'rotate-token':{const i=+el.dataset.index;return modal('Ruota API Token',`Ruotare <strong>${esc(state.api[i]?.name)}</strong>? Il vecchio token smetterà di funzionare.`, 'Ruota (demo)','modal-confirm',()=>{state.tokenReveal='kmp_demo_ROTATED_'+Math.random().toString(36).slice(2,13);log('superuser','token.rotate',state.api[i].id);render()})}case'revoke-oauth':{const i=+el.dataset.index;return modal('Revoca client OAuth',`Revocare <strong>${esc(state.oauth[i]?.name)}</strong> e i relativi grant?`, 'Revoca (demo)','modal-confirm',()=>{state.oauth[i].status='Revocato';log('superuser','oauth.revoke',state.oauth[i].id);render()})}case'add-origin':return addOrigin();case'focus-origin':return document.getElementById('originField')?.focus();case'remove-origin':{const i=+el.dataset.index;return modal('Rimuovi origine CORS',`Rimuovere <code>${esc(state.origins[i])}</code> dalla allowlist?`, 'Rimuovi (demo)','modal-confirm',()=>{state.origins.splice(i,1);render();toast('Origin rimossa nella simulazione.');log('superuser','cors.origin.remove','')})}case'test-cors':{const url=document.getElementById('corsProbe')?.value;const area=document.getElementById('corsResult');if(!url)return toast('Seleziona un’origine da verificare.','bad');area.innerHTML=`<div class="notice success">${ic('check',17)}<div><strong>Simulazione: OPTIONS 204, Host OK, initialize OK, tools/list OK</strong><div class="smalltext">Il test reale richiede richieste HTTP e Bearer al backend, qui non avviene.</div></div></div>`;state.tests.cors=true;return toast('Diagnostica demo completata.')}case'focus-file':return document.getElementById('demoFile')?.focus();case'upload':{const f=document.getElementById('demoFile')?.files?.[0];if(!f)return toast('Seleziona un file locale, senza inviarlo.','bad');if(f.size>100000000)return toast('Il limite per singolo file è 100 MB.','bad');const mode=document.getElementById('fileMode').value;state.files.unshift({name:f.name,size:f.size,mode:mode==='openlink'?'OpenLink':'Base64',status:'Completato'});log('mcp:demo','files.upload',f.name);toast('Upload simulato: solo metadati, nessun byte trasmesso.');return render()}case'job-detail':return modal('Dettagli job · demo',`<code>${esc(el.dataset.job)}</code><br><br>Qui il prodotto reale dovrebbe leggere <code>/api/v1/jobs/{id}</code> e gli eventi dell'installer, mostrare progressi e aggiornarsi anche dopo il riavvio del Core.`, 'Chiudi','modal-cancel');case'error-demo':return modal('Impossibile applicare la modifica','La sessione amministrativa è scaduta. <strong>Nessun cambiamento è stato salvato.</strong><br><br>Accedi nuovamente e ripeti l’azione. Questo messaggio sostituisce il JSON grezzo.','Ho capito','modal-cancel');case'edit-setting':return confirmEdit(el.dataset.key);case'edit-confirm':{const key=el.dataset.key,val=document.getElementById('editVal')?.value;closeModal();state.tests.settings=true;return applyValue(key,val)}case'apply-config':{const items=[...document.querySelectorAll('[data-config]')];if(!items.length)return;const edits=items.map(e=>[e.dataset.config,e.value]).filter(([k,val])=>state.cfg[k]!==val);if(!edits.length)return toast('Nessuna modifica da applicare.');return modal('Salva configurazione','Applica '+edits.length+' impostazione/i nella sola simulazione? In produzione è necessaria la conferma superuser.','Applica (demo)','modal-confirm',()=>{edits.forEach(([k,v])=>state.cfg[k]=v);log('superuser','deployment.batch.update',edits.map(x=>x[0]).join(', '));toast('Modifiche applicate nella simulazione.');render()})}case'scenario':return goto(v);case'reset-demo':return modal('Reimposta demo','Le modifiche simulated, il job e i risultati del test verranno azzerati ricaricando lo staging.','Reimposta','modal-confirm',()=>location.reload());case'modal-cancel':return closeModal();case'modal-confirm':{const fn=window.pendingConfirm;closeModal();if(fn)fn();return}default:return}}
document.addEventListener('click',event=>{const btn=event.target.closest('[data-action]');if(btn){event.preventDefault();actionClick(btn.dataset.action,btn)}});document.addEventListener('input',event=>{if(event.target.id==='allowedCidrs'||event.target.id==='deniedCidrs'){state.draftAllowed=document.getElementById('allowedCidrs').value;state.draftDenied=document.getElementById('deniedCidrs').value;state.scopeDirty=true;document.getElementById('probeResult').innerHTML=scopeResult(state.testIP)}else if(event.target.id==='probeIP'){state.testIP=event.target.value;document.getElementById('probeResult').innerHTML=scopeResult(state.testIP)}else if(event.target.id==='settingSearch'){const pos=event.target.selectionStart;state.search=event.target.value;const list=document.querySelector('tbody');if(list){const matches=configs.filter(x=>[x[0],x[1],x[4]].join(' ').toLowerCase().includes(state.search.toLowerCase()));list.innerHTML=matches.map(([key,group,type,def,desc])=>`<tr><td><strong class="mono">${esc(key)}</strong><div class="micro">${esc(desc)}</div></td><td>${badge(group,'blue')}</td><td><code>${esc(state.cfg[key]||'(vuoto)')}</code></td><td>${button('Modifica','edit-setting','small',`data-key="${key}"`)}</td></tr>`).join('')}}});document.addEventListener('keydown',e=>{if(e.key==='Escape'&&document.getElementById('overlay').children.length)closeModal()});startLive();
})();
