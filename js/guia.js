(function(){
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const reduce=window.matchMedia&&matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ---------- tema ---------- */
function applyTheme(t){if(t==='system')document.documentElement.removeAttribute('data-theme');else document.documentElement.setAttribute('data-theme',t);
  $$('.theme button').forEach(b=>b.setAttribute('aria-pressed',b.dataset.t===t));try{localStorage.setItem('ipv6-tema',t);}catch(_){}}
let _t='system';try{_t=localStorage.getItem('ipv6-tema')||'system';}catch(_){}
applyTheme(_t);
document.querySelector('.theme').addEventListener('click',e=>{const b=e.target.closest('[data-t]');if(b)applyTheme(b.dataset.t);});

/* ---------- OSI ---------- */
const OSI=[
 {n:7,nm:"Aplicação",tcp:"Aplicação",f:"A conversa do programa que você usa: pedir uma página, enviar um e-mail, traduzir um nome.",p:["HTTP","HTTPS","DNS","DHCP","SSH","SMTP","POP3","IMAP","FTP","SFTP","SNMP","NTP","Telnet","LDAP","RDP","MQTT"],d:"A rede entrega tudo, mas a aplicação erra: HTTP 500, DNS que não responde, login recusado.",v6:"DHCP ganha a versão DHCPv6 (portas 546/547) ou é dispensado pelo SLAAC. DNS ganha o registro AAAA. URLs com IPv6 usam colchetes: http://[2001:db8::1]/.",a:"Phishing, injeção de código, roubo de credenciais em protocolos de texto claro (Telnet, FTP, HTTP)."},
 {n:6,nm:"Apresentação",tcp:"Aplicação",f:"Traduz, comprime e cifra o conteúdo para que os dois lados entendam o mesmo formato.",p:["TLS","SSL (obsoleto)","MIME","ASCII","JPEG"],d:"Certificado expirado ou de outro nome, versão de TLS não aceita, caracteres trocados.",v6:"Nada muda: o TLS funciona igual sobre IPv4 e IPv6.",a:"Uso de SSL/TLS antigo, certificados falsos, ataques de rebaixamento de versão."},
 {n:5,nm:"Sessão",tcp:"Aplicação",f:"Abre, mantém e encerra o diálogo entre os dois lados.",p:["NetBIOS","RPC","PPTP","SOCKS"],d:"Sessões que caem ou expiram no meio do uso.",v6:"Nada muda.",a:"Sequestro de sessão (roubo de cookie ou token)."},
 {n:4,nm:"Transporte",tcp:"Transporte",f:"Entrega de ponta a ponta ao <b>programa certo</b> (portas), com controle de fluxo e de erros.",p:["TCP","UDP","QUIC","SCTP","DCCP"],d:"O host responde, mas a porta não. RST quase imediato = serviço parado. Nenhuma resposta = firewall descartando.",v6:"TCP e UDP são os mesmos; só o cabeçalho IP abaixo deles muda. No IPv6, o checksum do UDP passa a ser obrigatório.",a:"Varredura de portas (port scan), SYN flood (abrir milhares de conexões pela metade)."},
 {n:3,nm:"Rede",tcp:"Internet",f:"Endereçamento lógico (IP) e escolha do caminho entre redes (rotas).",p:["IPv6","IPv4","ICMPv6","ICMP","IPsec","OSPF","BGP","IGMP"],d:"O pacote nem sai: sem rota, o erro “Network is unreachable” aparece na hora. Teste com ping no IP.",v6:"<b>Aqui mora o IPv6.</b> O ICMPv6 assume funções do ARP e do IGMP. Roteadores não fragmentam. O IPsec foi projetado junto com o IPv6.",a:"IP spoofing, RA falsa, sequestro de rotas BGP, ICMP mal filtrado."},
 {n:2,nm:"Enlace",tcp:"Acesso à rede",f:"Entrega dentro da rede local usando o endereço físico (MAC). Detecta erros no meio.",p:["Ethernet","Wi-Fi (802.11)","ARP","NDP*","VLAN 802.1Q","STP","PPP"],d:"Vizinhos não se enxergam: ARP ou NS sem resposta, <code>ip neigh</code> mostra FAILED.",v6:"O ARP sai e entra o <b>NDP</b> (NS/NA). *Tecnicamente o NDP é ICMPv6 (camada 3), mas resolve um problema de camada 2. Broadcast deixa de existir: multicast com MAC 33:33:…",a:"ARP spoofing e NA spoofing, MAC flooding, salto de VLAN."},
 {n:1,nm:"Física",tcp:"Acesso à rede",f:"O sinal em si: elétrico no cabo, luz na fibra, rádio no Wi-Fi.",p:["802.3 (cabo)","802.11 (Wi-Fi)","Fibra","DSL","RS-232"],d:"Cabo solto, LED da porta apagado, sinal de Wi-Fi fraco.",v6:"Nada muda.",a:"Acesso físico a equipamentos, grampo em cabo, interferência de rádio (jamming)."}
];
let osiSel=3;
function renderOSI(){
  $('#osiStack').innerHTML=OSI.map(l=>`<button class="osi-l" data-l="${l.n}" aria-pressed="${l.n===osiSel}"><span class="num">${l.n}</span><span>${l.nm}</span><small>${l.n===3?'IPv6':''}</small></button>`).join('');
  const l=OSI.find(x=>x.n===osiSel);
  $('#osiDetail').innerHTML=`<h3>Camada ${l.n} · ${l.nm}</h3>
   <dl class="kv"><dt>O que faz</dt><dd>${l.f}</dd>
   <dt>No TCP/IP</dt><dd>Camada de ${l.tcp}</dd>
   <dt>Protocolos</dt><dd><div class="protos">${l.p.map(x=>`<span class="ptag">${x}</span>`).join('')}</div></dd>
   <dt>Quando falha</dt><dd>${l.d}</dd>
   <dt>No IPv6</dt><dd>${l.v6}</dd>
   <dt>Ataques típicos</dt><dd>${l.a}</dd></dl>`;
}
$('#osiStack').addEventListener('click',e=>{const b=e.target.closest('[data-l]');if(b){osiSel=+b.dataset.l;renderOSI();}});
renderOSI();

/* ---------- portas ---------- */
const PORTS=[
 ["ARP",2,"—","Descobre o MAC a partir do IPv4 (no IPv6: NDP)",""],
 ["BGP",3,"TCP 179","Roteamento entre sistemas autônomos (a Internet)",""],
 ["DHCP",7,"UDP 67/68","Entrega IP, máscara, gateway e DNS (Discover, Offer, Request, Ack)",""],
 ["DHCPv6",7,"UDP 546/547","Versão IPv6 do DHCP (Solicit, Advertise, Request, Reply)",""],
 ["DNS",7,"UDP/TCP 53","Traduz nomes em endereços IP (A, AAAA)",""],
 ["Ethernet",2,"—","Transporte na rede local cabeada",""],
 ["FTP",7,"TCP 20/21","Transferência de arquivos","claro|use SFTP ou FTPS"],
 ["HTTP",7,"TCP 80","Navegação web","claro|use HTTPS"],
 ["HTTPS",7,"TCP 443","Navegação web com TLS","cifrado"],
 ["ICMP",3,"—","Erros e testes no IPv4 (o ping usa)",""],
 ["ICMPv6",3,"—","Erros, testes e NDP no IPv6. Não bloquear tudo",""],
 ["IGMP",3,"—","Grupos multicast no IPv4 (no IPv6: MLD)",""],
 ["IMAP",7,"TCP 143/993","Lê e-mail mantendo a cópia no servidor","misto|143 claro, 993 com TLS"],
 ["IPsec",3,"UDP 500/4500","Cifra e autentica o tráfego IP (IKE nas portas)","cifrado"],
 ["IPv4",3,"—","Endereçamento de 32 bits",""],
 ["IPv6",3,"—","Endereçamento de 128 bits",""],
 ["LDAP",7,"TCP 389/636","Consulta diretórios de usuários","misto|389 claro, 636 com TLS"],
 ["MQTT",7,"TCP 1883/8883","Mensagens leves para IoT","misto|1883 claro, 8883 com TLS"],
 ["NDP",3,"—","Descoberta de vizinhos e roteadores no IPv6 (NS, NA, RS, RA)",""],
 ["NetFlow / IPFIX",7,"UDP 2055","Exporta resumos de fluxos de tráfego",""],
 ["NFS",7,"TCP 2049","Compartilha arquivos em Unix/Linux",""],
 ["NTP",7,"UDP 123","Sincroniza relógios (essencial para logs)",""],
 ["OSPF",3,"—","Roteamento interno por estado de enlace",""],
 ["POP3",7,"TCP 110/995","Baixa e-mail para o cliente","misto|110 claro, 995 com TLS"],
 ["PPP",2,"—","Enlace ponto a ponto",""],
 ["QUIC",4,"UDP 443","Transporte cifrado do HTTP/3","cifrado"],
 ["RDP",7,"TCP 3389","Área de trabalho remota do Windows","cifrado|não exponha à Internet"],
 ["SCTP",4,"—","Transporte com vários fluxos (telecom)",""],
 ["sFlow",7,"UDP 6343","Amostragem de pacotes para análise",""],
 ["SFTP",7,"TCP 22","Transferência de arquivos sobre SSH","cifrado"],
 ["SIP",7,"TCP/UDP 5060","Sinalização de voz e vídeo","claro|5061 com TLS"],
 ["SMB",7,"TCP 445","Compartilha arquivos no Windows","|nunca exponha à Internet"],
 ["SMTP",7,"TCP 25/587","Envia e-mail entre servidores","misto|use STARTTLS"],
 ["SNMP",7,"UDP 161/162","Monitora equipamentos de rede","claro|v1/v2c claro, use SNMPv3"],
 ["SSH",7,"TCP 22","Acesso remoto por linha de comando","cifrado"],
 ["SSL",6,"—","Antecessor do TLS","obsoleto|use TLS 1.2/1.3"],
 ["STP",2,"—","Evita loops na rede local",""],
 ["TCP",4,"—","Entrega confiável e ordenada",""],
 ["Telnet",7,"TCP 23","Acesso remoto por linha de comando","claro|use SSH"],
 ["TLS",6,"—","Cifra a conexão (base do HTTPS)","cifrado"],
 ["UDP",4,"—","Entrega rápida, sem garantia",""],
 ["VLAN 802.1Q",2,"—","Divide a rede local em redes lógicas",""]
];
const PF=[["todos","Todos"],["claro","Texto claro"],["cifrado","Cifrado"],["2","Camada 2"],["3","Camada 3"],["4","Camada 4"],["7","Camada 7"]];
let pf='todos';
const SECL={claro:"Texto claro",cifrado:"Cifrado",misto:"Depende da porta",obsoleto:"Obsoleto"};
function renderPorts(){
  const q=($('#portQ').value||'').toLowerCase();
  $('#portF').innerHTML=PF.map(([k,l])=>`<button class="chip" data-f="${k}" style="${pf===k?'color:var(--accent);border-color:var(--accent);border-style:solid':''}" aria-pressed="${pf===k}">${l}</button>`).join('');
  const rows=PORTS.filter(r=>{const [sec]=r[4].split('|');
    if(pf==='claro'&&!(sec==='claro'||sec==='obsoleto'||sec==='misto'))return false;
    if(pf==='cifrado'&&sec!=='cifrado')return false;
    if(/^\d$/.test(pf)&&String(r[1])!==pf)return false;
    return !q||r.join(' ').toLowerCase().includes(q);});
  $('#portT').innerHTML=rows.length?rows.map(([p,c,port,f,s])=>{const [sec,note]=s.split('|');
    return `<tr><td><b>${p}</b></td><td>${c}</td><td><code>${port}</code></td><td>${f}</td><td>${sec?`<span class="sec-b ${sec}">${SECL[sec]}</span>`:''}${note?`<div class="explain" style="font-size:.82rem;margin-top:4px">${note}</div>`:''}</td></tr>`;}).join('')
    :'<tr><td colspan="5" class="explain">Nada encontrado.</td></tr>';
}
$('#portF').addEventListener('click',e=>{const b=e.target.closest('[data-f]');if(b){pf=b.dataset.f;renderPorts();}});
$('#portQ').addEventListener('input',renderPorts);
renderPorts();

/* ---------- hero ---------- */
(function(){
  const g="2001:0db8:cafe:0001:0000:0000:0000:0001".split(":");
  $('#heroHex').innerHTML=g.map((h,i)=>`<span class="hx ${i<4?'net':'iid'}">${h}</span>`).join('<span class="colon">:</span>');
})();

/* ---------- experiments ---------- */
const EXPS={
 1:[
  {id:"1.1",t:"Neighbor Solicitation e Neighbor Advertisement",s:"O “ARP” do IPv6",
   one:"Para mandar um pacote a um vizinho, o aparelho precisa do endereço físico (MAC) dele. O NDP descobre isso com duas mensagens.",
   how:["O nó envia uma <b>NS</b> (Neighbor Solicitation, ICMPv6 tipo 135): “quem tem o IP X? Qual seu MAC?”.","A NS vai para um endereço multicast especial, o <b>solicited-node</b> (<code>ff02::1:ffXX:XXXX</code>, formado pelos últimos 24 bits do IP procurado). Assim só os interessados são incomodados, diferente do broadcast do ARP.","O dono responde com uma <b>NA</b> (Neighbor Advertisement, tipo 136) contendo o MAC.","A resposta fica guardada no cache de vizinhos (<code>ip -6 neigh</code>)."],
   lab:"Um <code>ping6</code> entre dois nós ligados diretamente, capturando NS e NA no Wireshark.",
   sec:"Ninguém confere se a NA é verdadeira. Um atacante pode responder “o IP X sou eu” e receber o tráfego da vítima. É o <b>NA spoofing</b>, o equivalente ao ARP spoofing, e permite ataques man-in-the-middle."},
  {id:"1.2",t:"Router Solicitation",s:"“Tem algum roteador aí?”",
   one:"Quando a interface de rede liga, o nó pergunta se há um roteador na rede em vez de esperar.",
   how:["O nó envia uma <b>RS</b> (Router Solicitation, tipo 133) para <code>ff02::2</code>, o grupo de todos os roteadores.","O roteador responde com um RA (próxima experiência)."],
   lab:"Desativar e reativar a interface de um nó e capturar a RS e o RA de resposta.",
   sec:"Uma RS revela que um aparelho acabou de entrar na rede, informação útil para quem está monitorando o enlace."},
  {id:"1.3",t:"Router Advertisement",s:"O roteador se apresenta",
   one:"O roteador anuncia periodicamente para todos (<code>ff02::1</code>) que existe, qual o prefixo da rede e como os nós devem se configurar.",
   how:["A <b>RA</b> (tipo 134) traz: prefixo da rede, tempo de vida do roteador como gateway padrão, MTU e flags.","Flag <b>M</b> (Managed): “peça endereço ao DHCPv6”. Flag <b>O</b> (Other): “peça outras informações, como DNS, ao DHCPv6”.","Os nós passam a usar quem enviou a RA como rota padrão."],
   lab:"Observar as RAs periódicas e os campos de cada uma no Wireshark.",
   sec:"Qualquer máquina pode enviar uma RA falsa (<b>rogue RA</b>) e se tornar o gateway de toda a rede, interceptando tudo. Defesas: <b>RA Guard</b> nos switches e monitoramento (extra)."},
  {id:"1.4",t:"Detecção de endereços duplicados (DAD)",s:"“Esse endereço já está em uso?”",
   one:"Antes de usar um endereço, o nó verifica se outro aparelho já o utiliza.",
   how:["O nó envia uma NS perguntando pelo próprio endereço que quer usar, com origem <code>::</code> (ainda não tem endereço válido).","Se alguém responder com NA, o endereço está duplicado e o nó não o usa.","Se ninguém responder, o endereço é assumido."],
   lab:"Trocar o endereço de um nó para um já em uso e observar a detecção. O nó original continua funcionando normalmente.",
   sec:"Esse mecanismo é a base do ataque da Experiência 3.1: um atacante responde a <b>todas</b> as verificações dizendo “é meu”, e nenhum aparelho novo consegue endereço."},
  {id:"1.5",t:"SLAAC com Quagga",s:"Autoconfiguração sem servidor",
   one:"No <b>SLAAC</b> (Stateless Address Autoconfiguration), o nó monta o próprio endereço: prefixo /64 recebido na RA + identificador da interface que ele mesmo gera.",
   how:["O roteador (aqui o software Quagga) anuncia o prefixo na RA.","O nó combina o prefixo com seu identificador (EUI-64 a partir do MAC, ou aleatório).","Não existe servidor guardando quem recebeu qual endereço, por isso “stateless”."],
   lab:"Configurar o Quagga para anunciar um prefixo e ver o endereço gerado no cliente.",
   sec:"Sem registro central, fica mais difícil saber qual aparelho usou qual endereço numa investigação. Logs do cache de vizinhos ou do switch ajudam."},
  {id:"1.6",t:"SLAAC com radvd",s:"Endereço, rota e DNS automáticos",
   one:"O mesmo SLAAC, agora com o software radvd, que também anuncia o servidor DNS dentro da RA (opção <b>RDNSS</b>).",
   how:["radvd envia RAs com prefixo e DNS.","No cliente, o <code>rdnssd</code> lê a opção RDNSS e configura o DNS.","Resultado: endereço, rota padrão e DNS sem DHCP."],
   lab:"Topologia com roteador (radvd), servidor DNS (BIND) e cliente.",
   sec:"Uma RA falsa também pode anunciar um <b>DNS falso</b>, redirecionando a vítima para sites maliciosos."},
  {id:"1.7",t:"DHCPv6 stateful",s:"Servidor distribui e registra endereços",
   one:"Funciona como o DHCP do IPv4: um servidor entrega o endereço e guarda o registro de quem recebeu qual.",
   how:["Quatro mensagens: <b>Solicit → Advertise → Request → Reply</b>.","O cliente usa a porta UDP 546 e o servidor a 547. O cliente envia para o multicast <code>ff02::1:2</code> (todos os agentes DHCP).","O servidor também informa o DNS recursivo.","Importante: o DHCPv6 <b>não informa o gateway</b>. Ele continua vindo da RA."],
   lab:"Configurar o servidor e analisar cada uma das quatro mensagens no Wireshark.",
   sec:"Facilita auditoria, porque há um registro de concessões. Um servidor DHCPv6 falso pode distribuir configurações maliciosas (defesa: DHCPv6 Guard nos switches, extra)."},
  {id:"1.8",t:"DHCPv6 stateless",s:"SLAAC para endereço, DHCPv6 para o resto",
   one:"O nó cria o endereço via SLAAC e só pede ao DHCPv6 informações extras, como DNS. O servidor não precisa guardar nada sobre os clientes.",
   how:["A RA vem com a flag <b>O</b> ligada.","O cliente gera o endereço sozinho e consulta o DHCPv6 só para o DNS."],
   lab:"Configurar o roteador com a flag O e o servidor para informar o DNS.",
   sec:"Combina as fraquezas dos dois mundos: depende de RAs confiáveis e de um servidor DHCPv6 legítimo."},
  {id:"1.9",t:"DHCPv6 Prefix Delegation",s:"O provedor entrega uma rede inteira",
   one:"O provedor entrega ao roteador do cliente (CPE) um bloco inteiro, por exemplo um <b>/56</b>, e o CPE o divide em redes /64.",
   how:["Um /56 contém 256 redes /64.","O CPE anuncia um /64 diferente em cada sub-rede interna via RA.","Os aparelhos usam SLAAC em cada sub-rede."],
   lab:"Simular um provedor entregando um /56 a um cliente com duas sub-redes.",
   sec:"Com IPv6 e sem NAT, os aparelhos internos têm endereços públicos. O NAT nunca foi um mecanismo de segurança, mas muitas redes dependiam dele como “filtro”. Agora o <b>firewall stateful no CPE</b> é obrigatório."},
  {id:"1.10",t:"Path MTU Discovery",s:"Pacote grande demais",
   one:"No IPv6, os roteadores <b>não fragmentam</b> pacotes. Se o pacote for grande demais, o roteador o descarta e avisa a origem, que fragmenta.",
   how:["O roteador envia um ICMPv6 <b>Packet Too Big</b> (tipo 2) informando o MTU do próximo enlace.","A origem passa a mandar pacotes menores.","O MTU mínimo garantido no IPv6 é 1280 bytes."],
   lab:"Reduzir o MTU de uma rede, enviar pings grandes e ver a origem fragmentar.",
   sec:"Se o firewall bloquear Packet Too Big, conexões grandes “travam” sem erro aparente (o chamado <b>buraco negro de PMTU</b>). É o motivo número um de não bloquear todo o ICMPv6."}
 ],
 2:[
  {id:"2.1",t:"DNS: consultas",s:"Servidor recursivo com BIND",
   one:"O registro <b>AAAA</b> é o “A” do IPv6: traduz um nome para um endereço IPv6.",
   how:["Um servidor responde AAAA e A independentemente de a consulta ter chegado por IPv4 ou IPv6.","A resposta é idêntica nos dois casos."],
   lab:"Configurar um recursivo BIND e consultar com <code>dig AAAA</code>.",
   sec:"Restrinja quem pode usar seu recursivo (<code>allow-query</code>/<code>allow-recursion</code>) também para endereços IPv6. Recursivos abertos são usados em ataques de amplificação (extra)."},
  {id:"2.2",t:"DNS: servidor autoritativo",s:"Ativar IPv6 num DNS existente",
   one:"Três passos para levar um DNS autoritativo ao IPv6.",
   how:["Fazer o servidor escutar em IPv6 (<code>listen-on-v6</code>).","Adicionar registros AAAA para os nomes.","Configurar o reverso em <code>ip6.arpa</code>, onde o endereço é escrito ao contrário, um dígito hexadecimal por vez."],
   lab:"Modificar um servidor que só respondia IPv4.",
   sec:"Se o reverso não estiver configurado, ferramentas de log e e-mail podem tratar os endereços como suspeitos."},
  {id:"2.3",t:"HTTP: páginas novas no Apache",s:"IPv6 sem configurar nada",
   one:"O Apache aceita conexões IPv6 por padrão.",
   how:["Basta iniciar o serviço.","Na URL, o endereço IPv6 vai entre colchetes: <code>http://[2001:db8::1]/</code>."],
   lab:"Iniciar o Apache e acessar por IPv6.",
   sec:"Exposição silenciosa: serviço acessível por IPv6 mesmo que o time ache que só existe IPv4."},
  {id:"2.4",t:"HTTP: páginas existentes no Apache",s:"VirtualHost num IPv6 específico",
   one:"Configurar um VirtualHost para responder em um endereço IPv6 específico.",
   how:["Usar a sintaxe com colchetes: <code>&lt;VirtualHost [2001:db8::10]:80&gt;</code> e <code>Listen [2001:db8::10]:80</code>."],
   lab:"Adaptar um site que já funcionava em IPv4.",
   sec:"Confira se as restrições de acesso (por IP) do site também cobrem os endereços IPv6."},
  {id:"2.5",t:"HTTP: Nginx",s:"Suportado, mas desligado por padrão",
   one:"O Nginx precisa de uma linha a mais para escutar em IPv6.",
   how:["Adicionar <code>listen [::]:80;</code> no bloco <code>server</code>."],
   lab:"Habilitar IPv6 no Nginx.",
   sec:"Regras <code>allow</code>/<code>deny</code> por IP precisam incluir prefixos IPv6."},
  {id:"2.6",t:"Proxy web direto (Squid)",s:"Ponte entre redes IPv4 e IPv6",
   one:"Um proxy com pilha dupla permite que clientes só IPv6 acessem sites só IPv4, e o contrário.",
   how:["O cliente fala com o proxy em um protocolo.","O proxy busca o conteúdo no outro protocolo."],
   lab:"Configurar o Squid nos dois sentidos.",
   sec:"Restrinja quem pode usar o proxy (ACLs), incluindo origens IPv6. Proxies abertos são abusados."},
  {id:"2.7",t:"Proxy web reverso",s:"Publicar um site só IPv6 para a Internet IPv4",
   one:"O proxy fica na frente do servidor, recebe pedidos em IPv4 e os repassa em IPv6, funcionando também como cache.",
   how:["Clientes IPv4 → proxy → servidor somente IPv6."],
   lab:"Observar o cliente usando IPv4 e o servidor respondendo em IPv6.",
   sec:"Os logs do servidor passam a mostrar o IP do proxy. Para auditoria, registre o cabeçalho com o IP original do cliente (extra)."},
  {id:"2.8",t:"Samba",s:"Compartilhamento de arquivos só com IPv6",
   one:"Disponibilizar uma pasta compartilhada para um cliente usando apenas IPv6.",
   how:["Configuração básica do Samba e acesso pelo endereço IPv6."],
   lab:"Cliente acessa a pasta via IPv6.",
   sec:"Compartilhamento de arquivos nunca deve ficar exposto à Internet. Com endereços IPv6 públicos, o firewall precisa bloquear as portas SMB vindas de fora."}
 ],
 3:[
  {id:"3.1",t:"Ataque DoS ao NDP",s:"Ninguém mais entra na rede",attack:true,
   one:"Uma máquina maliciosa (no lab, <code>n3Faker</code>) responde a <b>todas</b> as mensagens de DAD dizendo que já usa o endereço verificado. Nenhum novo aparelho consegue endereço.",
   how:["Um malware na rede escuta as NS de DAD.","Para cada uma, envia uma NA falsa: “esse endereço é meu”.","O nó novo desiste do endereço. Tenta outro e acontece o mesmo.","É uma negação de serviço (DoS) feita só com mensagens legítimas do protocolo."],
   lab:"Ver o ataque acontecer e depois detectá-lo com o <b>NDPMon</b>, que monitora mensagens NDP, gera logs e pode alertar o administrador.",
   sec:"Defesas: monitoramento (NDPMon), <b>SEND</b> (SEcure Neighbor Discovery, que assina as mensagens com criptografia, porém pouco adotado), e recursos de segurança nos switches que limitam quem pode enviar mensagens NDP."},
  {id:"3.2",t:"Firewall stateful",s:"Filtrar sem quebrar o IPv6",
   one:"Boas práticas de firewall IPv6 com <code>ip6tables</code>, seguindo a RFC 4890.",
   how:["<b>Stateful</b>: guarda o estado das conexões e só deixa entrar respostas a pedidos feitos de dentro.","<b>Stateless</b>: decide pacote a pacote, só por regras fixas.","Política padrão DROP nas cadeias INPUT, OUTPUT e FORWARD, com liberações explícitas.","Bloquear o <b>Routing Header tipo 0</b> (<code>--rt-type 0</code>), obsoleto e usado para amplificação de tráfego.","Bloquear prefixos que nunca deveriam aparecer, como <code>3ffe::/16</code> (antiga rede de testes 6bone).","<b>Liberar as mensagens ICMPv6 essenciais</b> (use o simulador abaixo)."],
   lab:"Duas partes: firewall em um servidor (<code>n4Host</code>) e em um roteador. Depois, regras são alteradas de propósito para ver o que quebra.",
   sec:"Erro mais comum de quem vem do IPv4: bloquear todo o ICMP. Segundo erro: ter firewall IPv4 e esquecer o IPv6. São dois conjuntos de regras separados (<code>iptables</code> e <code>ip6tables</code>)."},
  {id:"3.3",t:"IPsec: modo transporte",s:"Criptografia entre dois hosts",
   one:"Proteger todo o tráfego entre duas máquinas, mesmo passando por roteadores no meio.",
   how:["Captura 1: ping sem IPsec, tudo legível.","Captura 2: com AH, legível mas autenticado.","Captura 3: com ESP, conteúdo criptografado.","Chaves geradas e inseridas com <code>setkey</code> (SAD e SPD)."],
   lab:"Hosts <code>n1HostABCD</code> e <code>n4Host1234</code>, com dois roteadores entre eles.",
   sec:"Mostra na prática a diferença entre integridade (AH) e confidencialidade (ESP)."},
  {id:"3.4",t:"IPsec: modo túnel",s:"VPN entre duas redes",
   one:"Um túnel IPsec entre dois roteadores criptografa todo o tráfego entre as redes <code>2001:db8:abcd::</code> e <code>2001:db8:1234::</code>.",
   how:["O pacote original inteiro, incluindo o cabeçalho IP, é criptografado e colocado dentro de um novo pacote entre os roteadores.","Os hosts não precisam de nenhuma configuração."],
   lab:"Configurar os roteadores e verificar a criptografia na captura.",
   sec:"Quem observa o caminho só vê os dois roteadores conversando e não sabe quais hosts estão se comunicando."}
 ],
 4:[
  {id:"4.1",t:"Túnel 6in4",s:"IPv6 dentro de IPv4",
   one:"Dois nós com pilha dupla trocam IPv6 através de um roteador que só entende IPv4, encapsulando o pacote.",
   how:["O pacote IPv6 vai dentro de um pacote IPv4 com protocolo número <b>41</b>.","O túnel é configurado manualmente nas duas pontas."],
   lab:"Ver na captura o pacote IPv6 dentro do IPv4.",sec:"Filtre o protocolo 41 onde túneis não são esperados."},
  {id:"4.2",t:"Túnel GRE",s:"Encapsulamento genérico",
   one:"Mesma ideia do 6in4, usando o GRE, que pode carregar vários protocolos.",
   how:["Cabeçalho GRE entre o IPv4 externo e o IPv6 interno."],
   lab:"Comparar a captura com a do 6in4.",sec:"GRE não tem criptografia. Para proteger, combine com IPsec."},
  {id:"4.3",t:"DS-Lite",s:"IPv4 compartilhado sobre rede IPv6",
   one:"O provedor opera só IPv6 e ainda entrega IPv4 ao cliente, tunelado até um CGNAT central.",
   how:["No cliente, o <b>B4</b> encapsula IPv4 em IPv6.","No provedor, o <b>AFTR</b> desencapsula e faz o NAT."],
   lab:"Configurar B4 e AFTR.",sec:"Herda os problemas do CGNAT: um IPv4 identifica muitos clientes, então registrar porta e horário é essencial para investigações."},
  {id:"4.4",t:"6rd: relay e CPE (/64)",s:"IPv6 rápido sobre rede IPv4",
   one:"O provedor oferece IPv6 sem mudar sua rede IPv4: o prefixo IPv6 do cliente é derivado do seu IPv4.",
   how:["O <b>relay</b> do provedor e o <b>CPE</b> do cliente trocam IPv6 dentro de IPv4.","Cada cliente recebe um /64."],
   lab:"Configuração manual de relay e um CPE.",sec:"Variante do 6to4 controlada pelo provedor, mais previsível e segura que túneis automáticos públicos."},
  {id:"4.5",t:"6rd: CPEs com /56",s:"Várias redes por cliente",
   one:"Mesma técnica, agora entregando um /56 para cada um de três clientes.",
   how:["Cada CPE pode criar até 256 sub-redes /64."],
   lab:"Configurar relay e três CPEs.",sec:"Mais redes por cliente significa mais pontos onde o firewall do CPE precisa estar correto."},
  {id:"4.6",t:"NAT64 com TAYGA",s:"Cliente só IPv6 acessa site só IPv4",
   one:"Tradução de protocolos: o roteador reescreve pacotes IPv6 como IPv4 e vice-versa.",
   how:["<b>DNS64</b> (BIND): quando o site só tem registro A, o DNS “inventa” um AAAA embutindo o IPv4 num prefixo especial (como <code>64:ff9b::/96</code>).","<b>TAYGA</b>: traduz cada IPv6 para um IPv4 privado.","<b>iptables</b>: NAT44 para o IPv4 público do roteador."],
   lab:"Configurar os três componentes numa rede de provedor simplificada.",sec:"DNS64 não funciona bem com DNSSEC validado no cliente, porque a resposta é sintetizada (extra)."},
  {id:"4.7",t:"464XLAT",s:"Apps antigos em rede só IPv6",
   one:"Dupla tradução para que aplicativos que só falam IPv4 funcionem numa rede só IPv6, muito usado em redes móveis.",
   how:["<b>CLAT</b> (no cliente): traduz IPv4 → IPv6.","<b>PLAT</b> (o NAT64 do provedor): traduz IPv6 → IPv4 de volta.","É uma extensão natural do NAT64 da experiência anterior."],
   lab:"Adicionar um CPE como CLAT à topologia do NAT64.",sec:"Mais camadas de tradução tornam a rastreabilidade mais difícil. Registre os mapeamentos."}
 ],
 5:[
  {id:"5.1",t:"OSPFv3 com uma área",s:"Roteamento interno",
   one:"Os roteadores trocam informações sobre seus enlaces e cada um calcula o melhor caminho para todas as redes.",
   how:["OSPFv3 é a versão do OSPF para IPv6.","Os vizinhos se comunicam usando endereços <b>link-local</b>.","Tudo em uma única área (área 0, o backbone).","Configurado no Quagga."],
   lab:"Montar a vizinhança, verificar a tabela de rotas e derrubar enlaces para ver a convergência.",sec:"Roteador falso pode injetar rotas. Use autenticação entre vizinhos e não ative OSPF em interfaces voltadas a usuários."},
  {id:"5.2",t:"BGP",s:"Roteamento entre organizações",
   one:"O protocolo que mantém a Internet conectada. Cada AS anuncia suas redes aos vizinhos.",
   how:["<b>eBGP</b>: sessão entre AS diferentes.","<b>iBGP</b>: sessão dentro do mesmo AS.","Políticas influenciam o tráfego de saída (ex.: <i>local-preference</i>) e de entrada (ex.: <i>AS-path prepend</i>)."],
   lab:"Estabelecer sessões iBGP e eBGP e depois aplicar políticas de roteamento.",sec:"Filtre o que aceita e o que anuncia. Anúncios indevidos podem desviar tráfego de outras redes."}
 ]
};
function renderExps(ch){
  const box=$('#exps-'+ch); if(!box) return;
  box.innerHTML=EXPS[ch].map(e=>`
  <details class="exp">
    <summary><span class="exp-id">${e.id}</span><span class="exp-title">${e.t}${e.attack?'<span class="pill">ATAQUE</span>':''}<small>${e.s}</small></span><span class="chev" aria-hidden="true">▶</span></summary>
    <div class="exp-body">
      <p>${e.one}</p>
      <h4>Como funciona</h4><ul>${e.how.map(h=>`<li>${h}</li>`).join('')}</ul>
      <h4>No laboratório</h4><p>${e.lab}</p>
      <div class="callout sec"><span class="tag">Olhar de segurança</span><p>${e.sec}</p></div>
    </div>
  </details>`).join('');
}
[1,2,3,4,5].forEach(renderExps);

/* ---------- IPv6 address tool ---------- */
function parseV6(input){
  let s=input.trim().toLowerCase();
  if(!s) throw "Digite um endereço.";
  s=s.replace(/^\[|\]$/g,'');
  let prefix=null;
  if(s.includes('/')){const p=s.split('/');s=p[0];prefix=parseInt(p[1],10);if(isNaN(prefix)||prefix<0||prefix>128) throw "Prefixo inválido (use /0 a /128).";}
  s=s.split('%')[0];
  // embedded IPv4
  const m4=s.match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if(m4){const o=m4.slice(1).map(Number);if(o.some(x=>x>255)) throw "IPv4 embutido inválido.";
    s=s.slice(0,-m4[0].length)+((o[0]<<8)|o[1]).toString(16)+':'+((o[2]<<8)|o[3]).toString(16);}
  if((s.match(/::/g)||[]).length>1) throw "Só pode haver um “::” no endereço.";
  let groups;
  if(s.includes('::')){
    const [a,b]=s.split('::');
    const ga=a?a.split(':'):[], gb=b?b.split(':'):[];
    const fill=8-ga.length-gb.length;
    if(fill<1) throw "Grupos demais para usar “::”.";
    groups=[...ga,...Array(fill).fill('0'),...gb];
  } else groups=s.split(':');
  if(groups.length!==8) throw `Um endereço completo tem 8 grupos. Este tem ${groups.length}.`;
  groups.forEach(g=>{if(!/^[0-9a-f]{1,4}$/.test(g)) throw `“${g}” não é um grupo válido (até 4 dígitos de 0 a f).`;});
  const full=groups.map(g=>g.padStart(4,'0'));
  let big=0n; full.forEach(g=>{big=(big<<16n)|BigInt(parseInt(g,16));});
  return {full,big,prefix};
}
function compress(full){
  const g=full.map(x=>x.replace(/^0+(?=.)/,''));
  let bs=-1,bl=0,cs=-1,cl=0;
  g.forEach((x,i)=>{if(x==='0'){if(cs<0){cs=i;cl=1;}else cl++; if(cl>bl){bl=cl;bs=cs;}}else{cs=-1;cl=0;}});
  if(bl<2) return g.join(':');
  const left=g.slice(0,bs).join(':'), right=g.slice(bs+bl).join(':');
  return left+'::'+right;
}
const inNet=(big,net,len)=>{const n=parseV6(net).big;const sh=BigInt(128-len);return (big>>sh)===(n>>sh);};
function classify(big){
  const R=[
    ["::",128,"Não especificado","Usado como origem quando o nó ainda não tem endereço, por exemplo no DAD (Exp. 1.4)."],
    ["::1",128,"Loopback","A própria máquina, como 127.0.0.1 no IPv4."],
    ["::ffff:0:0",96,"IPv4 mapeado","Representa um IPv4 dentro de um programa IPv6."],
    ["64:ff9b::",96,"NAT64 (prefixo conhecido)","Endereço sintetizado pelo DNS64 para alcançar um IPv4 (Exp. 4.6)."],
    ["2001:db8::",32,"Documentação","Reservado para exemplos. Todo o laboratório do livro usa este bloco. Nunca aparece na Internet real."],
    ["2001::",32,"Teredo","Túnel automático IPv6 sobre UDP. Pode contornar firewalls: bloqueie se não usar."],
    ["2001:2::",48,"Benchmarking","Reservado para testes. O firewall da Exp. 3.2 bloqueia este bloco."],
    ["2001:10::",28,"ORCHID (obsoleto)","Bloco especial. O firewall da Exp. 3.2 bloqueia."],
    ["2002::",16,"6to4","Túnel automático antigo. Pode contornar filtros."],
    ["3ffe::",16,"6bone (obsoleto)","Antiga rede de testes do IPv6, desativada. O firewall da Exp. 3.2 bloqueia."],
    ["ff02::1",128,"Multicast: todos os nós","Para onde o roteador envia as RAs (Exp. 1.3)."],
    ["ff02::2",128,"Multicast: todos os roteadores","Para onde vão as RS (Exp. 1.2)."],
    ["ff02::1:2",128,"Multicast: agentes DHCPv6","Para onde o cliente DHCPv6 envia Solicit (Exp. 1.7)."],
    ["ff02::1:ff00:0",104,"Multicast solicited-node","Usado pelo NDP nas NS para descobrir vizinhos e no DAD (Exp. 1.1 e 1.4)."],
    ["ff00::",8,"Multicast","Um para vários. Não existe broadcast no IPv6."],
    ["fe80::",10,"Link-local","Válido só no enlace local. Todo aparelho IPv6 tem um. Usado pelo NDP e pelo OSPFv3."],
    ["fc00::",7,"Unique Local (ULA)","Endereço privado, como 10.x ou 192.168.x no IPv4."],
    ["2000::",3,"Global unicast","Endereço público, roteável na Internet. Precisa de firewall."]
  ];
  for(const [n,l,name,desc] of R) if(inNet(big,n,l)) return {name,desc};
  return {name:"Reservado / não atribuído",desc:"Não pertence a nenhum bloco de uso comum."};
}
function analyze(){
  const out=$('#addrOut');
  try{
    const {full,big,prefix}=parseV6($('#addrIn').value);
    const c=classify(big);
    const isMc=full[0].startsWith('ff');
    const hex=full.map((h,i)=>`<span class="hx ${isMc?'net':(i<4?'net':'iid')}">${h}</span>`).join('<span class="colon">:</span>');
    const sn=isMc?null:compress(['ff02','0000','0000','0000','0000','0001','ff'+full[6].slice(2),full[7]]);
    out.innerHTML=`<div class="hextets" style="font-size:1.05rem">${hex}</div>
    <dl class="out">
      <dt>Tipo</dt><dd><span class="badge">${c.name}</span></dd>
      <dt>O que é</dt><dd style="font-family:var(--f-body)">${c.desc}</dd>
      <dt>Forma curta</dt><dd>${compress(full)}${prefix!==null?'/'+prefix:''}</dd>
      <dt>Forma completa</dt><dd>${full.join(':')}</dd>
      ${isMc?'':`<dt>Prefixo /64</dt><dd>${compress([...full.slice(0,4),'0','0','0','0'])}/64</dd>
      <dt>ID da interface</dt><dd>${full.slice(4).map(x=>x.replace(/^0+(?=.)/,'')).join(':')}</dd>
      <dt>Solicited-node</dt><dd>${sn} <span style="font-family:var(--f-body);color:var(--muted)">(para onde vão as NS que procuram este endereço)</span></dd>`}
    </dl>`;
  }catch(e){out.innerHTML=`<p class="err">${esc(e)}</p>`;}
}
const EX=["fe80::200:ff:feaa:0","2001:db8:cafe:1::1","2001:0db8:0000:0000:0000:ff00:0042:8329","ff02::1","ff02::1:ff00:2","fd12:3456:789a::1","64:ff9b::192.0.2.33","::1","3ffe::1"];
$('#addrChips').innerHTML=EX.map(x=>`<button class="chip" data-a="${x}">${x}</button>`).join('');
$('#addrChips').addEventListener('click',e=>{const b=e.target.closest('[data-a]');if(!b)return;$('#addrIn').value=b.dataset.a;analyze();});
$('#addrGo').addEventListener('click',analyze);
$('#addrIn').addEventListener('keydown',e=>{if(e.key==='Enter')analyze();});
analyze();

function eui(){
  const out=$('#macOut');
  const raw=$('#macIn').value.trim().toLowerCase().replace(/[-.]/g,':');
  const hexs=raw.includes(':')?raw.split(':'):raw.match(/.{1,2}/g)||[];
  if(hexs.length!==6||hexs.some(h=>!/^[0-9a-f]{1,2}$/.test(h))){out.innerHTML='<p class="err">MAC inválido. Use 6 pares, por exemplo 00:1a:2b:3c:4d:5e.</p>';return;}
  const b=hexs.map(h=>parseInt(h,16));
  const f=b[0]^0x02;
  const bytes=[f,b[1],b[2],0xff,0xfe,b[3],b[4],b[5]];
  const grp=[0,2,4,6].map(i=>((bytes[i]<<8)|bytes[i+1]).toString(16).padStart(4,'0'));
  const ll=compress(['fe80','0000','0000','0000',...grp]);
  out.innerHTML=`<dl class="out">
    <dt>1. Dividir o MAC</dt><dd>${hexs.slice(0,3).join(':')} | ${hexs.slice(3).join(':')}</dd>
    <dt>2. Inserir ff:fe</dt><dd>${hexs.slice(0,3).join(':')}:<b>ff:fe</b>:${hexs.slice(3).join(':')}</dd>
    <dt>3. Inverter 7º bit</dt><dd>${b[0].toString(16).padStart(2,'0')} → <b>${f.toString(16).padStart(2,'0')}</b> (${b[0].toString(2).padStart(8,'0')} → ${f.toString(2).padStart(8,'0')})</dd>
    <dt>ID da interface</dt><dd>${grp.map(x=>x.replace(/^0+(?=.)/,'')).join(':')}</dd>
    <dt>Link-local</dt><dd><span class="badge">${ll}</span></dd>
  </dl>`;
}
$('#macGo').addEventListener('click',eui);
$('#macIn').addEventListener('keydown',e=>{if(e.key==='Enter')eui();});
eui();

/* ---------- NDP simulator ---------- */
const NODES={A:{x:90,name:"Host A",sub:"novo na rede"},B:{x:270,name:"Host B",sub:"2001:db8::2"},R:{x:450,name:"Roteador",sub:"fe80::1"},X:{x:630,name:"Atacante",sub:"n3Faker",att:true}};
const COL={ns:"var(--accent)",na:"var(--ok)",rs:"var(--iid)",ra:"var(--warn)",bad:"var(--bad)",icmp:"var(--muted)"};
const SCEN={
 nsna:{label:"Descobrir vizinho (NS/NA)",steps:[
  {f:"A",to:["B","R","X"],k:"ns",m:"NS",tx:"A quer pingar 2001:db8::2 mas não sabe o MAC. Envia uma <b>Neighbor Solicitation</b> para o multicast solicited-node <code>ff02::1:ff00:2</code>. Só quem tem um endereço terminado em <code>00:0002</code> processa."},
  {f:"B",to:["A"],k:"na",m:"NA",tx:"B reconhece o próprio endereço e responde com uma <b>Neighbor Advertisement</b> unicast, contendo seu MAC."},
  {f:"A",to:["B"],k:"icmp",m:"ping",tx:"A guarda o MAC no cache de vizinhos (<code>ip -6 neigh</code>) e envia o <b>Echo Request</b>."},
  {f:"B",to:["A"],k:"icmp",m:"pong",tx:"B responde com <b>Echo Reply</b>. Comunicação estabelecida."}]},
 rsra:{label:"Descobrir roteador (RS/RA)",steps:[
  {f:"A",to:["R","B","X"],k:"rs",m:"RS",tx:"A interface de A acabou de ligar. A envia uma <b>Router Solicitation</b> para <code>ff02::2</code> (todos os roteadores). Só o roteador responde."},
  {f:"R",to:["A","B","X"],k:"ra",m:"RA",tx:"O roteador responde com uma <b>Router Advertisement</b> para <code>ff02::1</code> (todos os nós): prefixo <code>2001:db8::/64</code>, “use-me como gateway”, flags M e O."},
  {f:null,tx:"A combina o prefixo <code>2001:db8::/64</code> com seu identificador de interface (<b>SLAAC</b>) e define o roteador como rota padrão. Antes de usar o endereço, ainda fará o DAD."}]},
 dad:{label:"DAD: endereço livre e duplicado",steps:[
  {f:"A",to:["B","R","X"],k:"ns",m:"NS",tx:"A gerou o endereço <code>2001:db8::a</code>. Antes de usar, envia uma NS com origem <code>::</code> perguntando “alguém usa <code>2001:db8::a</code>?”."},
  {f:null,tx:"Ninguém respondeu dentro do tempo limite. O endereço está livre e A passa a usá-lo."},
  {f:"A",to:["B","R","X"],k:"ns",m:"NS",tx:"Agora A tenta <code>2001:db8::2</code>, que já pertence a B. Envia a NS de DAD."},
  {f:"B",to:["A","R","X"],k:"na",m:"NA",tx:"B responde com uma NA para <code>ff02::1</code>: “esse endereço é meu”. A marca o endereço como <b>duplicado</b> e não o usa. B continua funcionando normalmente."}]},
 dos:{label:"Ataque DoS ao DAD (Exp. 3.1)",steps:[
  {f:"A",to:["B","R","X"],k:"ns",m:"NS",tx:"A gerou <code>2001:db8::a</code> e faz o DAD normalmente."},
  {f:"X",to:["A","B","R"],k:"bad",m:"NA!",tx:"O <b>atacante</b> escuta todas as NS de DAD e responde a cada uma: “esse endereço é meu”. É mentira, mas o protocolo não tem como verificar."},
  {f:"A",to:["B","R","X"],k:"ns",m:"NS",tx:"A desiste e tenta outro endereço, <code>2001:db8::b</code>."},
  {f:"X",to:["A","B","R"],k:"bad",m:"NA!",tx:"O atacante responde de novo. Qualquer endereço que A tentar será “roubado”."},
  {f:null,att:true,tx:"<b>Resultado: negação de serviço.</b> Nenhum aparelho novo consegue endereço. Detecção: o <b>NDPMon</b> registra o mesmo MAC reivindicando muitos endereços diferentes e alerta o administrador. Prevenção: SEND e proteções no switch."}]}
};
const svg=$('#sim'); let cur='nsna', idx=0, busy=false;
const NS="http://www.w3.org/2000/svg";
function drawBase(){
  let h=`<line class="bus" x1="40" y1="60" x2="680" y2="60"/><text class="s" x="40" y="44">enlace local (switch)</text>`;
  for(const [k,n] of Object.entries(NODES)){
    h+=`<line class="stem" x1="${n.x}" y1="60" x2="${n.x}" y2="130"/>
    <g class="node ${n.att?'attacker':''}" id="nd-${k}"><rect x="${n.x-72}" y="130" width="144" height="62" rx="10"/>
    <text class="n" x="${n.x}" y="158" text-anchor="middle">${n.name}</text><text class="s" x="${n.x}" y="178" text-anchor="middle">${n.sub}</text></g>`;
  }
  h+=`<g id="pkts"></g>`;
  svg.innerHTML=h;
}
function pathPts(a,b){const xa=NODES[a].x,xb=NODES[b].x;return [[xa,128],[xa,60],[xb,60],[xb,128]];}
function at(pts,t){
  const seg=[];let tot=0;for(let i=0;i<pts.length-1;i++){const d=Math.hypot(pts[i+1][0]-pts[i][0],pts[i+1][1]-pts[i][1]);seg.push(d);tot+=d;}
  let d=t*tot;for(let i=0;i<seg.length;i++){if(d<=seg[i]){const r=seg[i]?d/seg[i]:0;return [pts[i][0]+(pts[i+1][0]-pts[i][0])*r,pts[i][1]+(pts[i+1][1]-pts[i][1])*r];}d-=seg[i];}
  return pts[pts.length-1];
}
function send(step){
  return new Promise(res=>{
    const g=$('#pkts'); g.innerHTML='';
    $$('.sim .node').forEach(n=>n.classList.remove('hl'));
    if(!step.f){res();return;}
    $('#nd-'+step.f).classList.add('hl');
    const els=step.to.map(t=>{const e=document.createElementNS(NS,'g');e.setAttribute('class','pkt');
      e.innerHTML=`<circle r="13" fill="${COL[step.k]}"/><text y="-19" text-anchor="middle" fill="${COL[step.k]}">${step.m}</text>`;g.appendChild(e);return {e,p:pathPts(step.f,t)};});
    const dur=reduce?0:1300; const t0=performance.now();
    function fr(now){const t=dur?Math.min(1,(now-t0)/dur):1;const ez=t<.5?2*t*t:1-Math.pow(-2*t+2,2)/2;
      els.forEach(({e,p})=>{const [x,y]=at(p,ez);e.setAttribute('transform',`translate(${x},${y})`);});
      if(t<1)requestAnimationFrame(fr);else{step.to.forEach(t=>$('#nd-'+t).classList.add('hl'));res();}}
    requestAnimationFrame(fr);
  });
}
function renderLog(){
  const s=SCEN[cur].steps;
  $('#simLog').innerHTML=idx===0?`<p class="explain">Clique em <b>Próximo passo</b> para começar o cenário “${SCEN[cur].label}”.</p>`:
    s.slice(0,idx).map((st,i)=>`<div class="sim-step" style="${i<idx-1?'opacity:.55':''}"><b>${String(i+1).padStart(2,'0')}</b><span>${st.tx}</span></div>`).join('');
  $('#simCount').textContent=`Passo ${idx} de ${s.length}`;
  $('#simNext').disabled=idx>=s.length;
  $('#simNext').textContent=idx>=s.length?'Cenário concluído':'Próximo passo';
}
function setScen(k){cur=k;idx=0;drawBase();renderLog();$$('#simScen button').forEach(b=>b.setAttribute('aria-pressed',b.dataset.k===k));}
$('#simScen').innerHTML=Object.entries(SCEN).map(([k,v])=>`<button class="btn" data-k="${k}" aria-pressed="false">${v.label}</button>`).join('');
$('#simScen').addEventListener('click',e=>{const b=e.target.closest('[data-k]');if(b&&!busy)setScen(b.dataset.k);});
$('#simNext').addEventListener('click',async()=>{if(busy)return;const s=SCEN[cur].steps;if(idx>=s.length)return;busy=true;const st=s[idx];idx++;renderLog();await send(st);busy=false;});
$('#simReset').addEventListener('click',()=>{if(!busy)setScen(cur);});
setScen('nsna');

/* ---------- firewall ---------- */
const FW=[
 {t:"1",n:"Destination Unreachable",d:"Avisa que o destino não pode ser alcançado",rec:"allow",br:"Conexões para destinos inalcançáveis ficam esperando até estourar o tempo, em vez de falhar na hora."},
 {t:"2",n:"Packet Too Big",d:"Pacote maior que o MTU do caminho (Exp. 1.10)",rec:"allow",br:"<b>Path MTU Discovery quebra.</b> Páginas e downloads grandes travam sem erro (buraco negro de PMTU)."},
 {t:"3",n:"Time Exceeded",d:"Hop limit chegou a zero",rec:"allow",br:"<code>traceroute</code> deixa de funcionar e loops de roteamento ficam difíceis de diagnosticar."},
 {t:"4",n:"Parameter Problem",d:"Erro em cabeçalho do pacote",rec:"allow",br:"Erros de cabeçalho não são reportados. Falhas ficam silenciosas."},
 {t:"128/129",n:"Echo Request / Reply",d:"O ping",rec:"allow",br:"O ping para de funcionar. Não quebra a rede, mas atrapalha o diagnóstico. A RFC 4890 recomenda permitir, podendo limitar a taxa."},
 {t:"133",n:"Router Solicitation",d:"“Tem roteador aí?” (Exp. 1.2)",rec:"allow",br:"Nós recém-ligados demoram a achar o roteador, até a próxima RA periódica."},
 {t:"134",n:"Router Advertisement",d:"Prefixo e gateway (Exp. 1.3)",rec:"allow",br:"<b>SLAAC quebra:</b> ninguém recebe prefixo nem rota padrão. Sem acesso à Internet."},
 {t:"135",n:"Neighbor Solicitation",d:"Descoberta de vizinhos e DAD (Exp. 1.1, 1.4)",rec:"allow",br:"<b>A rede local para.</b> Ninguém descobre o MAC de ninguém, como bloquear o ARP no IPv4."},
 {t:"136",n:"Neighbor Advertisement",d:"Resposta com o MAC",rec:"allow",br:"<b>A rede local para.</b> As NS ficam sem resposta."},
 {t:"137",n:"Redirect",d:"Roteador indica caminho melhor",rec:"deny",br:"Nada essencial quebra. Bloquear é aceitável e até recomendado em muitas redes, pois Redirects falsos permitem desviar tráfego."}
];
const fwState={}; FW.forEach(r=>fwState[r.t]=r.rec);
function renderFW(){
  $('#fw').innerHTML=FW.map(r=>`<div class="fw-row ${fwState[r.t]==='deny'?'blocked':''}">
    <span class="t">${r.t}</span><span class="nm">${r.n}<small>${r.d}</small></span>
    <span class="seg" role="group" aria-label="${r.n}"><button class="${fwState[r.t]==='allow'?'on allow':''}" data-t="${r.t}" data-v="allow" aria-pressed="${fwState[r.t]==='allow'}">Permitir</button><button class="${fwState[r.t]==='deny'?'on deny':''}" data-t="${r.t}" data-v="deny" aria-pressed="${fwState[r.t]==='deny'}">Bloquear</button></span></div>`).join('');
  const broken=FW.filter(r=>r.rec==='allow'&&fwState[r.t]==='deny');
  const okRedirect=fwState["137"]==='deny';
  $('#fwStatus').innerHTML=broken.length?`<div class="fw-status broken"><strong>${broken.length} problema${broken.length>1?'s':''} na sua rede</strong><ul>${broken.map(r=>`<li><b>${r.n}:</b> ${r.br}</li>`).join('')}</ul></div>`
    :`<div class="fw-status good"><strong>Rede funcionando</strong><p>Todas as mensagens essenciais passam.${okRedirect?' Redirect bloqueado, o que reduz o risco de desvio de tráfego.':' Considere bloquear Redirect.'} Lembre que NS, NA, RS e RA só devem ser aceitas de endereços link-local e com hop limit 255, o que garante que vieram do próprio enlace.</p></div>`;
}
$('#fw').addEventListener('click',e=>{const b=e.target.closest('[data-t]');if(!b)return;fwState[b.dataset.t]=b.dataset.v;renderFW();});
$('#fwAll').addEventListener('click',()=>{FW.forEach(r=>fwState[r.t]='deny');renderFW();});
$('#fwRec').addEventListener('click',()=>{FW.forEach(r=>fwState[r.t]=r.rec);renderFW();});
renderFW();

/* ---------- IPsec ---------- */
const IPS={
 none:{pk:[["h","IPv6 (A → B)"],["h","ICMPv6"],["h data","dados: “abcdefgh…”"]],v:"Tudo legível",see:"Origem, destino, protocolo e o conteúdo do ping.",prot:"Nada. Qualquer um no caminho pode ler e alterar."},
 ah:{pk:[["h","IPv6 (A → B)"],["ah","AH"],["h","ICMPv6"],["h data","dados: “abcdefgh…”"]],v:"Legível, mas assinado",see:"Tudo continua legível, inclusive o conteúdo.",prot:"Integridade e autenticidade: qualquer alteração invalida o pacote, e B sabe que veio de A."},
 esp:{pk:[["h","IPv6 (A → B)"],["esp","ESP"],["enc data","ICMPv6 + dados criptografados"],["esp","ESP trailer"]],v:"Conteúdo cifrado",see:"Só origem, destino e que existe uma conversa ESP.",prot:"Confidencialidade (e integridade, se configurado). Ninguém sabe o que está sendo trocado."},
 tun:{pk:[["h","IPv6 (R1 → R2)"],["esp","ESP"],["enc data","IPv6 original (A → B) + ICMPv6 + dados, tudo cifrado"],["esp","ESP trailer"]],v:"Pacote inteiro cifrado",see:"Só os dois roteadores. Os hosts reais ficam ocultos.",prot:"Tudo do pacote original, inclusive quem está falando com quem. É uma VPN site a site."}
};
function renderIPS(m){
  const d=IPS[m];
  $('#ipsecPkt').innerHTML=`<span class="pk-label">Como o pacote aparece no Wireshark: <b>${d.v}</b></span><div class="pk">${d.pk.map(([c,t])=>`<div class="${c}">${t}</div>`).join('')}</div>`;
  $('#ipsecInfo').innerHTML=`<div class="card"><p class="eyebrow">O que um atacante vê</p><p>${d.see}</p></div><div class="card"><p class="eyebrow">O que fica protegido</p><p>${d.prot}</p></div>`;
  $$('#ipsecBtns button').forEach(b=>b.setAttribute('aria-pressed',b.dataset.m===m));
}
$('#ipsecBtns').addEventListener('click',e=>{const b=e.target.closest('[data-m]');if(b)renderIPS(b.dataset.m);});
renderIPS('none');

/* ---------- commands ---------- */
const CMDS=[
 ["ip -6 addr show","Lista os endereços IPv6 de cada interface (link-local, global...)."],
 ["ping -6 -c 4 2001:db8::2","Testa conectividade. No livro aparece como ping6."],
 ["ip -6 neigh show","Cache de vizinhos: IP e MAC aprendidos via NS/NA. Útil para detectar spoofing."],
 ["ip -6 route show","Tabela de rotas IPv6. Procure a rota default aprendida via RA."],
 ["traceroute -6 2001:db8::1","Mostra o caminho até o destino. Depende de ICMPv6 Time Exceeded."],
 ["dig AAAA exemplo.com.br","Consulta o registro AAAA (endereço IPv6) de um nome."],
 ["ss -tlnp","Mostra serviços escutando. Procure [::] para ver o que está exposto em IPv6."],
 ["ip6tables -L -n -v","Lista as regras do firewall IPv6. Separado do iptables!"],
 ["tcpdump -i eth0 -n icmp6","Captura ICMPv6 no terminal. No Wireshark, use o filtro icmpv6."],
 ["setkey -D","Mostra as associações de segurança (SAD) do IPsec."],
 ["nc -zv -6 2001:db8::1 443","Testa se uma porta TCP está aberta. “Connection refused” = serviço parado (camada 4)."],
 ["curl -6 -I https://exemplo.com.br","Faz um pedido HTTP(S) só por IPv6 e mostra o cabeçalho da resposta."]
];
$('#cmds').innerHTML=CMDS.map(([c,d],i)=>`<div class="cmd"><pre id="cmd${i}">${esc(c)}</pre><button class="copy" data-i="${i}">Copiar</button><p>${d}</p></div>`).join('');
$('#cmds').addEventListener('click',async e=>{const b=e.target.closest('.copy');if(!b)return;const txt=CMDS[b.dataset.i][0];
  try{await navigator.clipboard.writeText(txt);b.textContent='Copiado';}catch(_){const r=document.createRange();r.selectNodeContents($('#cmd'+b.dataset.i));const s=getSelection();s.removeAllRanges();s.addRange(r);b.textContent='Selecionado';}
  setTimeout(()=>b.textContent='Copiar',1500);});

/* ---------- glossary ---------- */
const GL=[
 ["6rd","IPv6 Rapid Deployment","Provedor entrega IPv6 por túnel sobre sua rede IPv4."],
 ["ARP","Address Resolution Protocol","No IPv4, descobre o MAC a partir do IP. No IPv6 foi substituído pelo NDP."],
 ["CGNAT","Carrier Grade NAT","NAT no provedor: muitos clientes compartilham um IPv4."],
 ["CPE","Customer Premises Equipment","O roteador na casa ou empresa do cliente."],
 ["DAD","Duplicate Address Detection","Verifica se um endereço já está em uso antes de usá-lo."],
 ["DHCPv6","Dynamic Host Configuration Protocol v6","Servidor que entrega endereço e configurações."],
 ["DNS","Domain Name System","Traduz nomes em endereços. AAAA para IPv6."],
 ["DNS64","DNS para NAT64","Sintetiza registros AAAA a partir de registros A."],
 ["DoS","Denial of Service","Ataque de negação de serviço: tornar algo indisponível."],
 ["DS-Lite","Dual-Stack Lite","IPv4 compartilhado entregue por túnel sobre rede IPv6."],
 ["ICMPv6","Internet Control Message Protocol v6","Mensagens de controle e erro. No IPv6 também faz o NDP. Não pode ser todo bloqueado."],
 ["IKE","Internet Key Exchange","Protocolo que troca chaves do IPsec com segurança."],
 ["IPsec","Internet Protocol Security","Autenticação e criptografia na camada de rede (AH e ESP)."],
 ["ISP","Internet Service Provider","Provedor de acesso à Internet."],
 ["MTU","Maximum Transmission Unit","Maior pacote que um enlace aceita. Mínimo de 1280 bytes no IPv6."],
 ["NA","Neighbor Advertisement","Resposta do NDP: “este IP é meu e meu MAC é este”."],
 ["NAT64","NAT de IPv6 para IPv4","Traduz pacotes entre os dois protocolos."],
 ["NDP","Neighbor Discovery Protocol","Descoberta de vizinhos, roteadores e endereços duplicados."],
 ["NDPMon","Neighbor Discovery Protocol Monitor","Ferramenta que monitora o NDP e alerta sobre anomalias."],
 ["NS","Neighbor Solicitation","Pergunta do NDP: “quem tem este IP?”."],
 ["OSPF","Open Shortest Path First","Roteamento interno. OSPFv3 é a versão para IPv6."],
 ["BGP","Border Gateway Protocol","Roteamento entre Sistemas Autônomos na Internet."],
 ["PMTUD","Path MTU Discovery","Descobre o maior pacote que passa pelo caminho todo."],
 ["RA","Router Advertisement","Anúncio do roteador com prefixo e gateway."],
 ["RS","Router Solicitation","Pedido de um nó para que o roteador se anuncie."],
 ["SA","Security Association","Acordo de chaves e algoritmos entre dois pontos IPsec."],
 ["SAD","Security Association Database","Tabela de SAs (chaves) do IPsec."],
 ["SEND","SEcure Neighbor Discovery","NDP com assinatura criptográfica contra falsificação."],
 ["SLAAC","Stateless Address Autoconfiguration","O nó monta o próprio endereço com o prefixo da RA."],
 ["SPD","Security Policy Database","Políticas do IPsec: o que proteger e como."],
 ["Túnel","Encapsulamento","Levar um protocolo dentro de outro (ex.: IPv6 dentro de IPv4)."],
 ["Dual stack","Pilha dupla","Rodar IPv4 e IPv6 ao mesmo tempo no mesmo aparelho."],
 ["OSI","Open Systems Interconnection","Modelo de referência que divide a comunicação em 7 camadas."],
 ["TCP","Transmission Control Protocol","Transporte confiável: combina a conexão (SYN, SYN-ACK, ACK), confirma e reenvia."],
 ["UDP","User Datagram Protocol","Transporte rápido e sem garantia. Usado em DNS, voz, vídeo e jogos."],
 ["Porta","Número de 0 a 65535","Identifica qual programa dentro do aparelho recebe o pacote (ex.: 443 = HTTPS)."],
 ["Handshake","Aperto de mão","Troca inicial para abrir uma conexão TCP ou combinar chaves no TLS e no SSH."],
 ["TLS","Transport Layer Security","Cifra a conexão (base do HTTPS). Use as versões 1.2 ou 1.3."],
 ["SSL","Secure Sockets Layer","Antecessor do TLS. Todas as versões são obsoletas."],
 ["SSH","Secure Shell","Acesso remoto cifrado (porta 22). Substitui o Telnet."],
 ["Telnet","Teletype Network","Acesso remoto em texto claro (porta 23). Inseguro."],
 ["HTTPS","HTTP Secure","HTTP dentro do TLS (porta 443)."],
 ["DHCP","Dynamic Host Configuration Protocol","Entrega IP no IPv4 em 4 passos: Discover, Offer, Request, Ack (DORA)."],
 ["NTP","Network Time Protocol","Sincroniza relógios (UDP 123). Essencial para logs e certificados."],
 ["SNMP","Simple Network Management Protocol","Monitora equipamentos. v1/v2c em texto claro; use v3."],
 ["MLD","Multicast Listener Discovery","Equivalente IPv6 do IGMP, dentro do ICMPv6."],
 ["SNI","Server Name Indication","Nome do site enviado no início do TLS. Ainda visível para quem está no caminho."]
];
function renderGloss(q){q=(q||'').toLowerCase();
  const items=GL.filter(g=>!q||g.join(' ').toLowerCase().includes(q));
  $('#gloss').innerHTML=items.length?items.map(([a,b,c])=>`<div class="g"><b>${a}</b><i>${b}</i><p>${c}</p></div>`).join(''):'<p class="explain">Nenhum termo encontrado.</p>';}
$('#glossQ').addEventListener('input',e=>renderGloss(e.target.value));
renderGloss();

/* ---------- quiz ---------- */
const QZ=[
 {q:"Qual protocolo do IPv6 substitui o ARP do IPv4?",o:["DHCPv6","NDP (Neighbor Discovery Protocol)","OSPFv3","SLAAC"],a:1,e:"O NDP usa mensagens ICMPv6 NS e NA para descobrir o MAC dos vizinhos."},
 {q:"Por que bloquear todo o ICMPv6 no firewall é um erro grave?",o:["Porque o ping deixa de funcionar","Porque o ICMPv6 carrega NDP e Packet Too Big, e a rede para de funcionar","Porque o IPsec depende do ICMPv6","Não é um erro, é a recomendação da RFC 4890"],a:1,e:"Sem NS/NA não há descoberta de vizinhos, sem RA não há SLAAC e sem Packet Too Big o PMTUD quebra."},
 {q:"No ataque da Experiência 3.1, o que o atacante faz?",o:["Envia RAs falsas","Responde a todas as verificações de DAD dizendo que já usa o endereço","Inunda o roteador com pings","Quebra a criptografia do IPsec"],a:1,e:"Ele envia NAs falsas para cada NS de DAD, e nenhum nó novo consegue endereço. É uma negação de serviço."},
 {q:"Qual ferramenta o livro usa para detectar ataques ao NDP?",o:["Wireshark","Squid","NDPMon","TAYGA"],a:2,e:"O NDPMon monitora mensagens NDP, gera logs e pode alertar o administrador."},
 {q:"Qual a diferença principal entre AH e ESP no IPsec?",o:["AH criptografa, ESP só autentica","AH autentica e garante integridade; ESP também criptografa","Os dois são iguais","ESP só funciona em modo túnel"],a:1,e:"O AH prova quem enviou e que nada foi alterado, mas o conteúdo continua legível. O ESP esconde o conteúdo."},
 {q:"Um endereço que começa com fe80:: é:",o:["Público, roteável na Internet","Link-local, válido só no enlace","Multicast","De documentação"],a:1,e:"fe80::/10 é link-local. Todo aparelho IPv6 tem um, e ele é usado pelo NDP."},
 {q:"No IPv6, quem fragmenta pacotes grandes demais?",o:["Os roteadores no caminho","Apenas a origem, após receber Packet Too Big","O switch","Ninguém, pacotes grandes são proibidos"],a:1,e:"Roteadores IPv6 não fragmentam. Eles descartam o pacote e enviam ICMPv6 Packet Too Big para a origem."},
 {q:"Por que um serviço Apache pode ficar exposto mesmo com firewall configurado?",o:["Porque o Apache desativa o firewall","Porque ele escuta em IPv6 por padrão e o firewall pode ter só regras IPv4","Porque o Apache usa UDP","Porque o IPv6 ignora firewalls"],a:1,e:"iptables (IPv4) e ip6tables (IPv6) são conjuntos de regras separados. Esquecer o ip6tables deixa o serviço aberto."},
 {q:"Qual o risco de segurança dos túneis como 6in4 e Teredo?",o:["São lentos","Podem levar tráfego IPv6 por dentro do IPv4 sem ser inspecionado pelo firewall","Só funcionam com IPsec","Revelam a senha do Wi-Fi"],a:1,e:"O firewall vê só o pacote externo (protocolo 41 ou UDP). Bloqueie túneis que a organização não usa."},
 {q:"O “ping” é um protocolo?",o:["Sim, de camada 7","Não: é um programa que envia mensagens ICMP (camada 3), sem porta","Sim, usa a porta 7"],a:1,e:"Ping é uma ferramenta. O protocolo por trás é o ICMP (ou ICMPv6), que não usa portas."},
 {q:"Em qual camada do modelo OSI o IPv6 trabalha?",o:["Camada 2 (enlace)","Camada 3 (rede)","Camada 4 (transporte)","Camada 7 (aplicação)"],a:1,e:"IPv4 e IPv6 são protocolos de rede: endereçamento lógico e rotas."},
 {q:"Qual a principal vantagem do UDP sobre o TCP?",o:["Garante a entrega","Menos atraso e menos pacotes, sem garantia de entrega","É criptografado","Usa menos portas"],a:1,e:"Por isso DNS, voz e jogos usam UDP: rapidez importa mais do que reenviar."},
 {q:"Qual protocolo substitui com segurança o Telnet?",o:["FTP","SSH (porta 22)","SNMP","HTTP"],a:1,e:"Telnet envia tudo, inclusive senhas, em texto claro. O SSH cifra a sessão inteira."},
 {q:"Qual mensagem uma máquina maliciosa enviaria para se passar pelo gateway da rede?",o:["Router Advertisement falsa (rogue RA)","Neighbor Solicitation","DHCPv6 Solicit","Echo Request"],a:0,e:"Os nós aceitam como gateway quem envia RA. Uma RA falsa desvia o tráfego. A defesa é o RA Guard nos switches."}
];
let qState={};
function renderQuiz(){
  $('#quizBox').innerHTML=QZ.map((x,i)=>{const st=qState[i];
    return `<div class="q"><span class="qn">PERGUNTA ${i+1} DE ${QZ.length}</span><h4>${x.q}</h4><div class="opts">${x.o.map((o,j)=>{let c='';if(st!==undefined){if(j===x.a)c='right';else if(j===st)c='wrong';}
      return `<button class="opt ${c}" data-q="${i}" data-o="${j}" ${st!==undefined?'disabled':''}>${o}</button>`;}).join('')}</div>
      ${st!==undefined?`<p class="explain"><b style="color:${st===x.a?'var(--ok)':'var(--bad)'}">${st===x.a?'Correto.':'Não foi dessa vez.'}</b> ${x.e}</p>`:''}</div>`;}).join('');
  const n=Object.keys(qState).length, ok=Object.entries(qState).filter(([i,v])=>QZ[i].a===v).length;
  $('#score').textContent=n<QZ.length?`${n} de ${QZ.length} respondidas · ${ok} certas`:`Resultado: ${ok} de ${QZ.length} certas`;
}
$('#quizBox').addEventListener('click',e=>{const b=e.target.closest('.opt');if(!b||b.disabled)return;qState[b.dataset.q]=+b.dataset.o;renderQuiz();});
$('#quizReset').addEventListener('click',()=>{qState={};renderQuiz();});
renderQuiz();

/* ---------- progress (per-viewer convenience) ---------- */
const KEY='ipv6-estudos-done';
let done={};try{done=JSON.parse(localStorage.getItem(KEY)||'{}')||{};}catch(_){done={};}
const total=$$('.done-toggle').length;
function syncDone(){
  $$('.done-toggle').forEach(b=>{const on=!!done[b.dataset.done];b.setAttribute('aria-pressed',on);b.textContent=on?'✓ Estudado':'Marcar como estudado';});
  $$('#toc a').forEach(a=>a.classList.toggle('done',!!done[a.dataset.s]));
  const n=Object.values(done).filter(Boolean).length;
  $('#pbar').style.width=(n/total*100)+'%';
  $('#ptext').textContent=`${n} de ${total} seções estudadas`;
}
document.addEventListener('click',e=>{const b=e.target.closest('.done-toggle');if(!b)return;done[b.dataset.done]=!done[b.dataset.done];try{localStorage.setItem(KEY,JSON.stringify(done));}catch(_){}syncDone();});
syncDone();

/* ---------- active section in toc ---------- */
if('IntersectionObserver' in window){
  const io=new IntersectionObserver(ents=>{ents.forEach(en=>{if(en.isIntersecting){$$('#toc a').forEach(a=>a.classList.toggle('active',a.dataset.s===en.target.id));
    const act=$('#toc a.active');if(act&&window.innerWidth<=900)act.scrollIntoView({block:'nearest',inline:'center',behavior:reduce?'auto':'smooth'});}});},{rootMargin:'-30% 0px -60% 0px'});
  $$('main section').forEach(s=>io.observe(s));
}
})();
