# V8 — configuração por perna e recusas RPC XMR

**Entrega parcial. A inicialização completa, F7 generalizado, M.8/claim no runtime e execução/revelação XMR solicitados ainda não estão concluídos. As 16 rotas não estão operacionais neste ZIP.**

Base cumulativa: V7, SHA-256 `53de4640fd8f7491cf07a77c946daf0fc16b80f2c9a2f6d539265206375338b4`. O arquivo `STATUS-V8.json` é o estado atual; documentos V1–V7 são históricos.

## Código novo e comportamento

- `src/production_route_services.rs`: configuração versionada por posição, com serviço EVM/BTC/SOL/XMR e identificação de settlement/chain separados nas duas pernas. Representa 16 pares, inclusive duas pernas da mesma família; DOM continua sendo o centro comum exigido pela topologia. Verifica formato canônico, limites, endpoints, quorum, identidade da composição/registro e implantação autenticada. Constrói clientes concretos por posição. Não fornece assinaturas nem provas de funding.
- `src/production_run.rs`: lê `production-route-services.v8.json` no diretório de estado. Na ausência desse arquivo, migra em memória a configuração anterior EVM+BTC; um V8 presente e inválido não dispara fallback. **Após essa leitura, `legacy_deployments` e `into_legacy_clients` ainda limitam o grafo do runtime a EVM+BTC. A exigência não foi eliminada da execução.** As outras variantes de clientes não chegam ao loop completo.
- `src/production_children.rs` e `src/production_xmr_quorum.rs`: a composição do quorum preserva recusas duras. Txid trocado, gênese incompatível e resposta completa inválida tornam-se `Conflict`, mesmo com dois votos concordantes; indisponibilidade permanece voto ausente. Um quorum de `missed_tx` para o txid exato continua sendo ausência legítima.
- `../adapters/xmr-rpc-broadcast-blocking`: contradição de gênese antes/depois da consulta é `Rejected`; resposta HTTP completa malformada ou acima do limite também é `Rejected`. Status de key image exige exatamente um valor reconhecido. Falha de transporte, leitura interrompida, HTTP indisponível ou status BUSY permanecem `Retryable`.

O runner cumulativo `scripts/test_interop_hardening.py` também foi corrigido: seus alvos de processo agora são literais, selecionados por uma tabela fechada. Isso resolve uma falha do guard estático de CI reproduzida no V7, sem alterar o guard. Os verificadores leem nomes fixos de arquivo no diretório exclusivo da execução.

A política de recusa dura permite que um nó contraditório interrompa o progresso mesmo havendo maioria. Isso preserva o erro solicitado; não oferece disponibilidade bizantina contra esse nó. Endpoints configurados são premissas de confiança, não prova de independência. O adaptador XMR continua aceitando somente monerod via HTTP loopback.

## Testes entregues

Há **17 novos métodos Rust**, ainda não executados aqui: 6 de configuração, 3 de classificação de votos, 4 com servidores HTTP locais passando pelos leitores/quorum reais e 4 no adaptador RPC. Um teste anterior de gênese recebeu asserção mais específica.

Há 8 novos métodos Python: 6 para o verificador independente de configurações e 2 para o despacho de testes. A suíte ampla tem 119 métodos, incluindo os testes anteriores de políticas do repositório; o aumento da contagem total não significa 62 testes novos. O modo completo exporta as configurações diretamente dos testes Rust e só então as compara com o verificador Python. O modo offline testa o próprio verificador com fixtures Python; não simula um resultado Rust nem comprova integração entre chains.

```bash
python3 -m pip install -r crates/dom-interopd/scripts/requirements-v7.txt
python3 crates/dom-interopd/scripts/test_daemon_v8.py
```

Execute da raiz `dom-protocol`, em Linux com a toolchain do projeto, Git, compilador C, Clang, CMake e pkg-config. O runner executa testes Python e Rust, os dois verificadores independentes, build release e self-check. Não configura nós, não provisiona chaves e não executa swaps.

Para executar somente os testes disponíveis sem Rust:

```bash
python3 crates/dom-interopd/scripts/test_daemon_v8.py --offline
```

Os relatórios são gravados em `artifacts/daemon-v8/`, com comandos, logs e digest das fontes. Falta de compilador causa código de saída 2, nunca aprovação. `--format` é opcional, altera a formatação dos dois pacotes antes dos testes e registra os digests antes/depois.

## Pendências concretas

1. Bootstrap por perna com donos reais de signer, armazenamento, refund e transporte; remover a dependência residual EVM+BTC do grafo V10.
2. Integrar a prontidão bilateral anterior ao funding com F7 e a rodada M.8 posterior às âncoras; conectar o resultado ao claim Bitcoin e à recuperação. O construtor de fresh funding depende hoje da autoridade de claim posterior ao funding.
3. Versionar o F7 e suas representações no armazenamento de contratos para provas próprias de cada família. O verificador atual exige blocos e ancestralidade Bitcoin.
4. Implementar a autoridade de sweep XMR, com compartilhamento de chaves, assinatura autenticada pelo sidecar, destino de refund autenticado, bytes e key image verificados e persistência antes do broadcast.
5. Vincular uma origem de revelação DOM à composição para XMR upstream. Um sweep Monero não revela o escalar privado como uma claim adaptor Bitcoin; a recusa existente continua necessária até existir essa origem verificada.
6. Compilar e executar a campanha de funding → claim/refund → crash/recovery pelo daemon real para cada um dos 16 pares. Zero swaps foram executados neste ambiente.

A autorização para alterar módulos fora do daemon foi recebida e utilizada no RPC XMR. As demais pendências acima são trabalho não concluído, não falta de autorização. Esta versão não recebe nota 10/10 nem certificação de uso com fundos reais.
