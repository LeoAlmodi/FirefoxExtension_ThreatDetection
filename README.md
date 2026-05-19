# Firefox Extension Threat Detection

Extensao para Firefox que detecta e exibe ameacas a privacidade durante a navegacao web.

## Funcionalidades

- Listagem de dominios de terceira parte contactados por pagina
- Contagem e classificacao de cookies (1a/3a parte, sessao/persistente)
- Monitoramento de Web Storage (localStorage, sessionStorage) e IndexedDB
- Deteccao de browser fingerprinting (Canvas, WebGL, AudioContext)
- Identificacao de scripts suspeitos e tentativas de hijacking
- Deteccao de cookie syncing entre dominios
- Deteccao de supercookies (ETag e HSTS)
- Threat Score com metodologia documentada

## Instalacao

1. Abra o Firefox e acesse `about:debugging`
2. Clique em **Este Firefox**
3. Clique em **Carregar extensao temporaria**
4. Selecione o arquivo `manifest.json` dentro da pasta do projeto

## Uso

Apos instalar, acesse qualquer pagina web e clique no icone da extensao na barra de ferramentas para visualizar o painel.

## Estrutura do repositorio

```
repositorio/
├── manifest.json           # Manifesto da extensao (Manifest V2)
├── content.js              # Content script principal
├── fingerprint_hooks.js    # Hooks de fingerprinting (page world)
├── README.md               # Este arquivo
├── background/
│   └── background.js       # Background script (webRequest, cookies)
└── popup/
    ├── popup.html
    ├── popup.css
    └── popup.js            # Logica do popup e Threat Score
```

## Metodologia do Threat Score

Parte de 100 pontos e aplica penalidades cumulativas:

| Vetor                             | Penalidade         | Teto     |
|-----------------------------------|--------------------|----------|
| Dominio de terceira parte         | -2 por dominio     | -30      |
| Cookie de terceira parte          | -3 por cookie      | -15      |
| Supercookie (HSTS, ETag)          | -10 cada           | sem teto |
| Tecnica de fingerprinting ativa   | -8 por tipo        | -24      |
| Script de tracker conhecido       | -5 por script      | -20      |
| Cookie syncing detectado          | -5 por ocorrencia  | -10      |
| Redirecionamento suspeito         | -8 cada            | sem teto |

**Classificacao:**
- 70-100: Bom (verde)
- 40-69:  Moderado (laranja)
- 0-39:   Critico (vermelho)

## Requisitos

- Firefox 109 ou superior
