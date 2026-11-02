# IPv6 na Prática

Guia de estudos e laboratório interativo de IPv6 para quem está começando em cibersegurança.

- **Guia** (`index.html`): resumo do livro *Laboratório de IPv6* (NIC.br) em linguagem simples. Inclui endereços, protocolos e camadas, os 5 capítulos, um simulador de NDP, firewall ICMPv6, IPsec, quiz, glossário e comandos.
- **Laboratório** (`laboratorio.html`): 15 missões com terminal simulado, topologia animada e captura de pacotes no estilo Wireshark. Cada missão termina com um resumo de “como explicar para outra pessoa” e perguntas de verificação.

É um site 100% estático, em HTML, CSS e JavaScript puros. Não precisa de build, banco de dados nem servidor.

## Estrutura

```
ipv6-na-pratica/
├── index.html          guia de estudos (página inicial)
├── laboratorio.html    laboratório interativo
├── 404.html            página de erro
├── favicon.svg
├── css/
│   ├── base.css        estilos comuns
│   ├── guia.css
│   └── laboratorio.css
├── js/
│   ├── tema.js         aplica o modo claro/escuro antes de a página aparecer
│   ├── guia.js
│   └── laboratorio.js  motor da rede simulada e das missões
└── vercel.json         cabeçalhos de segurança HTTP
```

## Rodar no seu computador

Abra o `index.html` direto no navegador, ou sirva a pasta:

```bash
npx serve .
```

## Publicar no GitHub e no Vercel

1. Crie um repositório vazio no GitHub (por exemplo, `ipv6-na-pratica`).
2. Dentro desta pasta, rode:

   ```bash
   git init
   git add .
   git commit -m "IPv6 na Prática: guia e laboratório"
   git branch -M main
   git remote add origin https://github.com/SEU-USUARIO/ipv6-na-pratica.git
   git push -u origin main
   ```

3. No [Vercel](https://vercel.com/new), clique em **Import** no repositório e configure:
   - **Framework Preset:** Other
   - **Build Command:** deixe em branco
   - **Output Directory:** deixe em branco (a raiz)
4. Clique em **Deploy**. A cada `git push` na `main`, o Vercel publica a nova versão sozinho.

Alternativa sem GitHub: `npx vercel` dentro da pasta.

## Links diretos para missões

Cada missão tem um endereço próprio, útil para compartilhar com alunos:
`/laboratorio.html#missao-1` até `/laboratorio.html#missao-15`.

## Segurança do próprio site

O `vercel.json` aplica cabeçalhos HTTP de segurança em todas as páginas:

| Cabeçalho | O que faz |
|---|---|
| `Content-Security-Policy` | Só executa scripts do próprio site (nenhum script inline ou de terceiros). As fontes vêm só do Google Fonts. |
| `X-Frame-Options: DENY` e `frame-ancestors 'none'` | Impede que outro site carregue esta página dentro de um iframe (clickjacking). |
| `X-Content-Type-Options: nosniff` | O navegador não “adivinha” o tipo de arquivo. |
| `Referrer-Policy` | Não vaza o caminho completo para sites externos. |
| `Permissions-Policy` | Desliga câmera, microfone, localização e pagamento, que o site não usa. |

Depois do deploy, você pode conferir a nota em <https://securityheaders.com>.

## Dados e privacidade

O site não coleta nada. O progresso das missões, as seções estudadas e o tema ficam salvos apenas no `localStorage` do navegador de cada visitante.

## Próximos passos possíveis

- **Supabase:** login para salvar o progresso entre aparelhos, ou um placar das missões. Não é necessário para o site funcionar.
- Domínio próprio: em *Vercel → Settings → Domains*.

## Créditos

- Conteúdo baseado no livro *Laboratório de IPv6: aprenda na prática usando um emulador de redes*, da equipe IPv6.br / NIC.br (2015). Material original em <https://lab.ipv6.br> e curso gratuito em <https://ipv6.br>.
- A seção “Protocolos e camadas” e as missões 7, 9 e 13 se baseiam no artigo [Protocolos de rede](https://www.opservices.com.br/protocolos-de-rede/), da OpServices.
- As missões 11 (RA falsa) e 12 (cache envenenado) e as notas marcadas como “extra” complementam o livro.

Este é um material de estudo independente, sem vínculo oficial com o NIC.br ou a OpServices. As ferramentas de ataque do laboratório são simuladas e não executam nada de verdade.
