# beans-shield — Roteiros para 5 Vídeos (HeyGen)

Cada vídeo tem 60–90 segundos. Tom: técnico mas acessível, direto, confiante. Avatar: perfil profissional tech. Fundo: código/terminal ou gradiente escuro.

---

## Vídeo 1: "O que é o beans-shield?" (Introdução)

**Duração:** 75s  
**Objetivo:** Explicar o problema e apresentar a solução  
**Slides/visual sugerido:** Terminal com transação sendo avaliada em tempo real

---

**SCRIPT:**

Toda fintech que processa pagamentos em tempo real enfrenta o mesmo dilema: como bloquear fraudes sem adicionar latência e sem depender de uma caixa-preta de terceiros?

O beans-shield é uma engine de detecção de fraude open-source em Go, projetada para quem precisa de decisões em menos de 50 microssegundos.

Funciona assim: cada transação passa por três camadas de regras — globais, setoriais e customizadas. Cada regra que dispara contribui um score de risco. O resultado final é uma de três decisões: permitir, revisar ou bloquear.

Sem dependências externas. Sem vendor lock-in. Sem custos por transação.

Se você processa Pix, crypto, ou pagamentos de apostas no Brasil, o beans-shield foi feito pra você.

Instale com um comando, configure seus thresholds, e comece a bloquear fraudes hoje.

Link na descrição.

---

## Vídeo 2: "Como funciona em 60 segundos" (Demo técnica)

**Duração:** 60s  
**Objetivo:** Mostrar o código funcionando  
**Slides/visual sugerido:** Tela de código Go com highlight nos pontos-chave

---

**SCRIPT:**

Vou te mostrar o beans-shield funcionando em 60 segundos.

Primeiro: crio uma instância do Shield com `shield.New()`. Pronto — as regras padrão já estão ativas.

Segundo: monto a transação. ID, usuário, tipo — no caso "pix_out" — valor em centavos, e o IP de origem.

Terceiro: chamo `Evaluate`. O retorno traz a decisão, o nível de risco, o score numérico, e a lista de regras que dispararam.

Por baixo dos panos, o Shield mantém um velocity counter com janelas deslizantes. Ele sabe quantas transações esse usuário fez na última hora, quanto movimentou em 24 horas, e se esse destino é novo.

Tudo in-memory, zero I/O, menos de 50 microssegundos de latência.

Se precisar persistir as decisões, implemente a interface Persister — um método, cinco parâmetros. Está no README.

---

## Vídeo 3: "Regras para Betting & iGaming" (Sector-specific)

**Duração:** 90s  
**Objetivo:** Mostrar inteligência anti-fraude específica para apostas  
**Slides/visual sugerido:** Diagrama mostrando os 6 padrões de fraude

---

**SCRIPT:**

Se você opera um gateway de pagamentos para casas de apostas, sabe que fraude em betting é diferente. Não é só transação alta — é padrão de comportamento.

O beans-shield vem com seis regras específicas para o setor:

**Round-trip**: detecta quando um usuário deposita e saca 80% ou mais em 24 horas sem apostar. Padrão clássico de lavagem.

**Smurfing**: múltiplas contas vindas do mesmo IP no mesmo merchant. Três contas em uma hora? Flag.

**Structuring**: transações fragmentadas para ficar abaixo do limite de R$50 mil do COAF. Soma mais de R$45 mil em três ou mais operações no dia? Flag.

**Syndicate**: cinco ou mais saques do mesmo merchant em 10 minutos. Indica operação coordenada.

**Merchant velocity**: quando o merchant ultrapassa 150% do limite configurado por hora.

**Ticket deviation**: quando a média de valor das últimas 24 horas é três vezes maior que a dos últimos 30 dias.

Pra ativar, use `DefaultBettingConfig` com o ID do merchant. Ou customize cada threshold no `MerchantConfig`.

---

## Vídeo 4: "Custom Rules — Criando sua própria regra" (Tutorial)

**Duração:** 75s  
**Objetivo:** Ensinar a criar regras personalizadas  
**Slides/visual sugerido:** Code editor com step-by-step

---

**SCRIPT:**

O beans-shield vem com regras prontas, mas toda fintech tem suas particularidades. Deixa eu te mostrar como criar sua própria regra em 30 segundos de código.

Uma Rule tem dois campos: um nome em string e uma função Evaluate. Essa função recebe a transação e o velocity counter, e retorna dois valores: se disparou ou não, e qual o nível de risco.

Exemplo real: quero bloquear qualquer compra de crypto acima de R$50 mil feita de madrugada, entre meia-noite e seis da manhã.

Crio a rule, checo o tipo da transação, checo a hora, checo o valor. Se bater nas três condições: retorno `true` com `RiskHigh`.

Pra usar, passo essa regra junto com as default rules no construtor, usando `WithRules` e `append`.

Pronto. A partir de agora, qualquer transação que passar pelo Evaluate vai ser testada contra essa regra também.

Se sua regra precisa de contexto do merchant — como limites específicos por setor — use `MerchantRule` com `EvalContext` ao invés da Rule global. Mesmo padrão, mais contexto disponível.

---

## Vídeo 5: "Por que open-source? A tese do beans-shield" (Posicionamento)

**Duração:** 90s  
**Objetivo:** Explicar a estratégia e credibilidade OSS  
**Slides/visual sugerido:** Logos de reguladores + benchmark numbers

---

**SCRIPT:**

Por que a BeansTech está open-sourcing sua engine de fraude?

Primeiro: porque o ecossistema de pagamentos no Brasil está explodindo. São mais de 800 fintechs processando Pix, e a maioria delas não tem budget pra um Featurespace ou um Feedzai — soluções que custam centenas de milhares de reais por ano.

Segundo: porque transparência é um requisito regulatório. O BACEN e o COAF esperam que você consiga explicar por que uma transação foi bloqueada. "O modelo disse que era fraude" não é uma resposta aceitável. Com beans-shield, cada decisão vem com a lista exata de regras que dispararam e o score numérico.

Terceiro: porque queremos que o mercado inteiro seja mais seguro. Fraude não é um problema competitivo — é um problema de ecossistema. Quando um gateway cai por fraude, todo mundo perde.

O beans-shield nasceu em produção. Processa transações reais. Detectou fraude real. Agora está disponível pra qualquer fintech que queira proteção sem vendor lock-in.

MIT license. Fork, customize, mande PR. Se precisar de suporte enterprise, de regras customizadas pro seu setor, ou de integração com seu stack — a BeansTech está aqui.

Link do repositório na descrição.

---

## Notas de Produção para HeyGen

| Parâmetro | Valor |
|-----------|-------|
| **Avatar** | Masculino, 25-35, profissional tech (ou avatar custom do Matheus) |
| **Idioma** | Português brasileiro |
| **Velocidade da fala** | 1.0x – 1.1x (dinâmico, não lento) |
| **Background** | Vídeo 1-2: terminal/código escuro. Vídeo 3-4: diagrama/code editor. Vídeo 5: fundo clean corporativo |
| **CTA final** | "Link na descrição" + logo BeansTech + GitHub URL |
| **Música** | Lo-fi tech ambient, volume 15-20% |
| **Formato** | 16:9 landscape (YouTube/LinkedIn) |
| **Thumbnail text** | V1: "Fraud Detection em Go", V2: "50μs", V3: "Anti-Lavagem Betting", V4: "Custom Rules", V5: "Open Source Fintech" |
