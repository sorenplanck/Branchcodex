# V4 cumulativa — roteamento de duas pernas e recuperação EVM

Base: `mainnetswap`, commit `7d9d41a1fd4a67ed25bf437846c739ee18f5cb36`.
Branch local: `interop/security-hardening-20260908`. V1, V2 e V3 estão preservadas.
ZIP V3 de origem: SHA-256 `04e5b4b9204a6086c2b760228907faa2cc59df4452939f79fbd7ee0106cda338`.

**A V4 modifica o código executado pelo root atual e acrescenta a infraestrutura
para dois executores por rota. Não entrega ainda os 16 swaps completos pelo
daemon. Rust não foi compilado neste ambiente. A meta 10/10 não foi atingida.**

## Executar as mudanças desta versão

Extraia o ZIP em uma pasta nova, entre em `dom-protocol` e execute:

```bash
python3 scripts/test_interop_hardening.py --format --mode routing
```

Esse comando roda os verificadores Python, os testes Rust do roteador V4, a
recuperação EVM e o isolamento de arquivos. O teste do roteador exporta
`rust-route-trace-v4.json`; em seguida `route_trace_oracle.py` confere os
registros produzidos pelo Rust. Se o arquivo não for produzido, a verificação
falha. Cada execução usa uma pasta nova e não reaproveita uma fixture anterior.

Para a regressão cumulativa dos componentes:

```bash
python3 scripts/test_interop_hardening.py --format --mode components
```

Para incluir os scripts existentes Bitcoin regtest, contratos e Anvil:

```bash
python3 scripts/test_interop_hardening.py --format --mode full
```

Pré-requisitos: Linux, Python 3, Git, Rust/Cargo/rustfmt (workflow fixado em
1.96.1), compilador C, clang, cmake, pkg-config e dependências Cargo disponíveis
por rede ou cache. `full` também requer `bitcoind`, `bitcoin-cli`, `forge`,
`anvil` e curl. Nenhum desses comandos instala dependências. Os modos `routing`
e `components` não precisam de nós públicos nem de chaves reais.

Sem Rust, `python3 scripts/test_interop_hardening.py --mode offline` executa
23 testes Python: 15 existentes de Bitcoin e 8 do novo verificador de traces.
Os 8 novos testes usam traces sintéticos para testar o próprio verificador;
não são evidência de execução do roteador Rust. Relatórios e logs com hashes
ficam em `artifacts/interop-hardening/`. Saída 0: comandos concluídos; 1: falha;
2: ferramenta ausente. `full` continua sem certificar todas as rotas pelo daemon.

## Código novo e ligação ao runtime

### Topologia autenticada e roteador por perna

`production_route_topology.rs` deriva duas pernas dos inputs autenticados.
Exige exatamente uma família por perna, settlements distintos, DOM comum e
compatível com o deployment, digests não nulos, profile compatível com os
termos e capabilities resolvidas pelo registro. A topologia conserva termos,
registro, composição, chain, profile e deployment. A mesma família pode estar
nas duas posições, inclusive na mesma rede, com settlements distintos.

`production_child_router.rs` recebe dois owners concretos por uma enumeração
fechada de EVM/BTC/SOL/XMR. Confere a face e o settlement de cada owner antes de
instalá-lo. Materialização, externalização, observação e reconciliação usam
**rota + perna + settlement**, além dos vínculos de termos, registro, chain,
profile e deployment pertinentes à chamada. DOM continua obrigatório. O
roteador não assina, não transmite por conta própria e não fabrica evidências.

`production_run.rs` já usa esse construtor na forma EVM+BTC que consegue
provisionar. Portanto, o novo roteador participa do fluxo atual. Os
construtores legados usados pela fábrica anterior continuam disponíveis onde
necessário; não representam a nova composição de dois owners da mesma família.

### Fábrica de dois executores concretos

`compose_production_counterparty_children_v4`, em `production_children.rs`,
recebe recursos separados para origem e destino. Autentica os dois inputs,
exige topologias iguais e verifica a forma dos recursos das duas pernas antes
de abrir clientes ou adquirir leases. Reusa os construtores concretos EVM,
Bitcoin, Solana e Monero e conserva **as duas autoridades de refund** junto
com os children. Não aceita uma porta arbitrária fornecida pelo transporte.

Os paths explícitos de prebroadcast BTC, store SOL e store XMR não podem
apontar para o mesmo arquivo, inclusive por symlink ou hard link. Symlinks
pendentes são recusados. Essa checagem inicial não elimina por si só corridas
no filesystem: as proteções de abertura, propriedade e locking dos stores
continuam necessárias. Os IDs de autoridade SOL/XMR usam namespace do
settlement, evitando colisão entre as duas pernas da mesma família.

**Essa fábrica ainda não é chamada pelo bootstrap principal.** Ela cria a
forma dos children que conduz operações já preparadas; não concede signers
novos nem materialização de funding/claim ausente. O root depende da
generalização de signers, payout F6 e provisioning para chamá-la. Duas pernas
EVM com a mesma conta também exigem coordenação de nonces na preparação; dois
stores isolados não substituem essa garantia.

### Recuperação pública EVM conectada

`production_refund_arming.rs` deriva os termos exatos do lock EVM dos inputs
e do deployment autenticado. A nova fonte compartilha o adapter retido pelo
refund; não abre outra credencial ou cliente de assinatura.

`production_plan_source.rs` permite vincular a fonte ao lock **antes de existir
o txid de claim**. Após autorização de exposição pelo fluxo existente, exige
rota, composição, chain, txid, evidência e horário coerentes. Recoleta o evento
Claimed finalizado, exige o txid exato da exposição e chama a verificação
completa do adapter para aquele lock. Não fixa o primeiro txid recebido, não
aceita evento Refunded e não devolve um scalar em cache quando a recoleta falha.
O digest público de exposição continua sob autenticação do coordenador/rota;
esta fonte prova o evento do lock, não substitui aquela autoridade.

`production_run.rs` instala essa fonte no router de segredos. A retenção selada
e suas regras de recuperação existentes continuam em vigor: um segredo já
publicado não volta a ser privado por causa de reorg.

### Isolamento da extração Bitcoin e correção de direção

O handoff de extração Bitcoin agora carrega e verifica perna e settlement,
além dos vínculos anteriores de rota, composição, chain e txid. A devolução
de uma capacidade recusada volta ao child emissor, inclusive com duas pernas
Bitcoin. A identidade é retida pela autoridade de funding autenticada.

O root só fornece o instalador Bitcoin ao materializador quando BTC está na
origem. Antes, fornecia-o também em EVM→DOM→BTC, enquanto o materializador
exigia sua ausência nessa direção; isso causava recusa de inicialização.
Essa correção não resolve o bloqueio separado de M.8/materialization scope.

## Testes escritos e evidência efetivamente obtida

| Verificação | Conteúdo | Resultado neste ambiente |
|---|---|---|
| Python cumulativo | 23 métodos, incluindo 8 novos testes do oracle de traces | Passaram |
| Roteador Rust | 16 pares, chamadas intercaladas, funding/refund, DOM, mutações de identidade e scope | Escrito; não executado |
| Coordenador SQLite + roteador | 32 casos, duas pernas de cada par; intent persistido, fechamento/reabertura, reconciliação do mesmo attempt | Escrito; não executado |
| Recuperação EVM | Claim posterior à construção, reextração, adapter reconstruído, txid/contexto errado, finalização, reorg e refund | Escrito; não executado |
| Isolamento de arquivos | Mesmo path, hard link, symlink e symlink pendente | Escrito; não executado |
| Comparação Rust/Python V4 | Verificador separado para 384 registros exportados pelo roteador | Não executada; exige Rust |
| Swaps completos pelo binário | Funding → claim/refund → recuperação nas redes | Zero executados |

Os testes de roteador usam children instrumentados. O teste SQLite exercita o
store real, mas simula perda de processo por fechamento/reabertura; não mata
um daemon real em cada fronteira de fsync. Os testes EVM usam adapter real
sobre RPC determinístico. Nenhum desses resultados representa auditoria
independente, verificação formal ou taxa estatística de perdas em mainnet.

## Todas as combinações exigidas

São 12 pares entre famílias diferentes e 4 pares da mesma família: **16**.
Em cada célula, o caminho passa pela DOM. A matriz do roteador está implementada
para todos; a coluna operacional abaixo diz respeito ao root completo.

| Origem | Destino | Situação do root nesta V4 |
|---|---|---|
| BTC | EVM | Forma selecionável; novos planos BTC continuam recusados |
| EVM | BTC | Forma selecionável; corrigido instalador invertido; novos planos BTC recusados |
| BTC | BTC | Seleção/provisioning ainda exige exatamente uma EVM e uma BTC |
| EVM | EVM | Seleção/provisioning ainda exige exatamente uma EVM e uma BTC |
| BTC | XMR | Bloqueio XMR no root |
| BTC | SOL | Bloqueio SOL no root |
| EVM | XMR | Bloqueio XMR no root |
| EVM | SOL | Bloqueio SOL no root |
| XMR | BTC | Bloqueio XMR no root |
| XMR | EVM | Bloqueio XMR no root |
| XMR | XMR | Bloqueio XMR no root |
| XMR | SOL | Bloqueios XMR/SOL no root |
| SOL | BTC | Bloqueio SOL no root |
| SOL | EVM | Bloqueio SOL no root |
| SOL | XMR | Bloqueios SOL/XMR no root |
| SOL | SOL | Bloqueio SOL no root |

XMR tem semântica própria: gasto Monero não é fonte de extração do segredo
DOM/secp256k1 no protocolo atual. Sua composição precisa respeitar os papéis
DOM e as autoridades existentes. Não se converteu XMR em fonte fictícia, nem
se removeu a recusa do materializador que impede uma combinação incompatível.

## O que falta no objetivo de ponta a ponta

Continuam pendentes a generalização do bootstrap/signers/F6 para as duas
pernas; prontidão bilateral DOM; transporte M.8 pós-âncoras; instalação e
recuperação do claim Bitcoin no root; refresh temporal autenticado; ligação
dos fontes necessários SOL e papéis XMR; campanhas reais de crash/reorg/fees;
verificação formal ligada à implementação; experimentos de privacidade;
auditorias criptográficas/distribuídas e reprodução independente de builds.

Não basta remover os `RouteShape` nem preencher um `None`: esses bloqueios
impedem avançar sem preparação e recuperação autenticadas. A V4 contém
implementação e testes novos, mas não demonstra ainda operação completa de
nenhuma das 16 rotas. O JSON `STATUS-META-10.json` registra esse alcance.
