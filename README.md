# IPv6 na Prática

Guia de estudos e laboratório interativo de IPv6 para quem está começando em cibersegurança.

🌐 **Acesse:** https://ipv6-na-pratica.vercel.app
🧪 **Laboratório:** https://ipv6-na-pratica.vercel.app/laboratorio.html

## O que tem

- **Guia:** resumo do livro *Laboratório de IPv6* (NIC.br) em linguagem simples. Inclui endereços, protocolos e camadas, os 5 capítulos do livro, um simulador de NDP, firewall ICMPv6, IPsec, quiz, glossário e comandos.
- **Laboratório:** 15 missões com terminal simulado, topologia animada e captura de pacotes no estilo Wireshark. Vai do endereço /64 a ataques como RA falsa e cache envenenado, sempre com as defesas. Cada missão termina com um resumo de “como explicar para outra pessoa” e perguntas de verificação.

Cada missão tem um link próprio para compartilhar, por exemplo: [missão 11 (RA falsa)](https://ipv6-na-pratica.vercel.app/laboratorio.html#missao-11).

## Como usar

- **Online:** é só abrir o link acima, sem cadastro.
- **No seu computador:** baixe o repositório (**Code → Download ZIP**), descompacte e abra o `index.html` no navegador.
- **Sugestões e correções:** abra uma *issue* aqui no GitHub.

Site 100% estático, em HTML, CSS e JavaScript puros, sem build nem servidor.

## Segurança e privacidade

- O site não coleta nenhum dado. O progresso e o tema ficam salvos apenas no navegador de cada visitante.
- O `vercel.json` aplica cabeçalhos HTTP de segurança: Content-Security-Policy (só scripts do próprio site), proteção contra iframe (clickjacking), `nosniff`, Referrer-Policy e Permissions-Policy.
- As ferramentas de ataque do laboratório são simuladas e não executam nada de verdade.

## Créditos

- Conteúdo baseado no livro *Laboratório de IPv6: aprenda na prática usando um emulador de redes*, da equipe IPv6.br / NIC.br (2015). Material original em https://lab.ipv6.br e curso gratuito em https://ipv6.br.
- A seção “Protocolos e camadas” e as missões 7, 9 e 13 se baseiam no artigo [Protocolos de rede](https://www.opservices.com.br/protocolos-de-rede/), da OpServices.
- As missões 11 e 12 e as notas marcadas como “extra” complementam o livro.

Material de estudo independente, sem vínculo oficial com o NIC.br ou a OpServices.
