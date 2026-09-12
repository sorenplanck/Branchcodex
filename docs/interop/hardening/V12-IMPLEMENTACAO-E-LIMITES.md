# V12 — implementação e limites verificáveis

Esta versão continua a V11 entregue, árvore Git
`807f05442f81fc71c92a145f868fb6cf66cb404d`. É uma candidata de desenvolvimento.
Os três critérios solicitados ainda não estão concluídos no binário real.
O registro atual é `crates/dom-interopd/STATUS-V12.json`; os documentos das
versões anteriores são históricos.

## Código novo

| Frente | Implementação | Limite atual |
| --- | --- | --- |
| Claim DOM | Signer nativo de um participante, wallet opaca, vault separado por finalidade, recuperação de nonce e produção dos envelopes DSC1 | Falta completar a montagem dos materiais na inicialização e a finalização/transmissão V12 pelo root |
| Bootstrap das shares | Produtor de compromisso/revelação assinados, persistência antes da revelação, retomada dos mesmos materiais e vínculo ao capsule real | A montagem do artefato bilateral e o comando de inicialização não estão concluídos |
| F7 por família | Gate nativo, votos bilaterais `0x17`, custódia do funding DOM, consumo de âncoras EVM/SOL/XMR, seis mensagens de assinatura e pré-assinatura `0x0f` | O coletor e o pump existem; sua construção completa pelo root ainda depende do bootstrap |
| Recuperação XMR | Formação nativa das cinco transações, custódia criptografada, observação de C/D, journal de intenção antes da RPC, segunda observação e resposta com txid exato | A compensação pré-assinada tem a limitação de protocolo descrita abaixo |
| Funding XMR | Comando real `prepare-xmr-funding-v12`, preparação com `do_not_relay`, publicação privada durável; importação e envio dos bytes exatos condicionados à observação recente de C | A preparação ocorre antes do setup que fixa o txid; a montagem do driver de execução ainda não está ligada ao root |
| Leases | Renovação finita com o proprietário e epoch atuais, conectada ao loop universal e aos filhos | Uma autorização Bitcoin já emitida conserva seu próprio prazo; renovar a lease não o estende |
| Reinício | Origem imutável da sessão autenticada mesmo depois de o head avançar; handles SOL/XMR antigos recusados dentro da transação SQLite | Não substitui uma campanha de crashes do binário com as chains reais |
| Resultado econômico | Evento nativo `DomCompensatedV12`, distinto de refund XMR, com persistência atômica e cancelamento dos comandos pendentes da perna | A entrada genérica de eventos não autoriza compensação; falta ativar seu consumidor na composição da rota |

Nenhum caminho recebe um txid fictício para satisfazer uma exigência Bitcoin.
Ausência de transação e resposta para outro identificador continuam sendo
resultados diferentes. Uma resposta conflitante não vira ausência transitória.

O comando de preparação XMR, seu JSON de entrada e a retomada dos arquivos
privados estão documentados em `docs/V12_XMR_PRIVATE_FUNDING.md`. Esse comando
é utilizável separadamente da inicialização de uma rota; não transmite a
transação nem cria clientes BTC/EVM. Sua presença não remove o bloqueio da
execução integral descrito abaixo.

## Por que a compensação impede considerar a rota finalizada

O desenho atual entrega antecipadamente uma transação DOM comum, totalmente
assinada, que gasta D depois de uma altura definida. A validação dessa
transação pela DOM verifica suas regras nativas; ela não comprova que houve
funding XMR.

Um participante que retenha essa transação pode transmiti-la diretamente depois
do prazo, sem passar pelo daemon. Se o outro participante não executar o
cancelamento/refund oportunamente, a compensação pode ser cobrada mesmo sem o
depósito XMR. Exigir uma prova XMR no driver reduz o que o daemon aceita, mas
não acrescenta essa condição à transação que a rede DOM aceita.

Por isso, a recusa de inicialização XMR permanece. A margem de volatilidade,
o prazo maior da compensação e a confirmação do colateral antes do funding
XMR não resolvem, isoladamente, essa possibilidade. Fechá-la exige um
mecanismo de execução que torne a condição verificável na própria autorização
de gasto, ou uma alteração explícita das premissas do protocolo. Esta entrega
não afirma ter implementado tal mecanismo.

Também foi corrigida uma incompatibilidade da V11: o hash de recuperação da
prova de C precisa ser o hash do capsule nativo. A política de compensação
continua vinculada pelos termos assinados e por `assurance_policy_hash`.
Substituir o hash do capsule pelo hash da política tornava a formação nativa
do output impossível.

## Fronteiras que permanecem fechadas

O produtor de share de gasto da wallet compõe uma chave específica para o
template e a finalidade. A Store histórica espera, em certos caminhos, a chave
pública da share de formação de C. São valores diferentes. A V12 não elimina
essa verificação para forçar a assinatura: ainda falta completar a prova
nativa de origem das chaves por finalidade e sua utilização no bootstrap.
No lado XMR, o bootstrap também precisa comprovar, antes do depósito, que a
chave pública de gasto compartilhada corresponde à soma das shares vinculadas
à sessão. A validação do setup isolada não demonstra essa equação; a conferência
existente após funding não substitui sua exigência antes de travar XMR.

Uma pré-assinatura de claim pronta também não equivale a claim transmitido.
A adaptação, a persistência da exposição, a observação de admissão e o transporte
final V12 precisam terminar sob o mesmo proprietário antes de declarar a rota
funcional. O resultado econômico de compensação DOM deve permanecer distinto
de um refund efetivamente recebido em XMR.

As 16 combinações ordenadas entre BTC, EVM, SOL e XMR permanecem no escopo.
Nenhuma foi declarada validada de ponta a ponta nesta entrega.

## Executar os testes

Na raiz do repositório extraído:

```bash
python3 crates/dom-interopd/scripts/test_daemon_v12.py
```

O comando executa os testes de componentes, a compilação de produção e o
self-check, preservando os logs em `artifacts/daemon-v12`. Ele não transmite
swaps nem instala dependências. Para executar somente as verificações Python
e as regras de arquitetura:

```bash
python3 crates/dom-interopd/scripts/test_daemon_v12.py --offline
```

Os resultados efetivamente obtidos acompanham o ZIP. A análise sintática com
tree-sitter não valida tipos, lifetimes, dependências de linking ou execução.
Não há compilador Rust disponível neste ambiente; os novos testes Rust foram
escritos, mas não executados aqui. Testes Python aprovados não certificam os
componentes Rust nem a segurança financeira das rotas.

## Revisão das regras de arquitetura

A nova ponte de signer em `dom-actuator/src/contracts.rs` é aditiva e conserva
as verificações de binding, chain e posse opaca da share. As decisões existentes
de `Sponsor` não foram ampliadas.

Em `session_store.rs`, o perfil F7 V12 foi acrescentado aos seletores e aos
auditores de contexto, sequência, replay e pré-assinatura. O perfil precisa
da própria emissão/consumo e recusa coexistência com V1/V2. As verificações
`require_strict_phase1` e `is_strict_v1_authorized` permanecem. O gate de refund
persistido e as recusas de `Sponsor` foram preservados. A comparação de funções
e hashes está nas evidências do ZIP; a atualização do hash congelado registra
esta revisão e não significa aprovação de uma auditoria externa.
