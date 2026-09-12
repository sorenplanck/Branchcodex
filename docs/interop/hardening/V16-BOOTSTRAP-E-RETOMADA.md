# V16 — bootstrap operacional e retomada

Base cumulativa: árvore V15 `2db8f56aa4a02fbe5bd24879b5fc1ca3a3325fad`.

Esta versão acrescenta código ao caminho executado pelo daemon. **Não conclui os seis blocos solicitados, não fecha as 16 rotas e não constitui uma avaliação 10/10.** Não houve compilação nem execução Rust neste ambiente. Os testes Rust descritos abaixo foram escritos para execução no ambiente do operador.

## Código novo no processo

`production_bootstrap_runtime_v16.rs` conduz as mensagens DSC1 `0x01`–`0x0a` usando as shares privadas já montadas pela cerimônia V13. O Stage12 mantém um condutor para cada posição. `ProductionCompositeRelayLoopV1::step_leg` chama esse condutor antes da transmissão e da leitura do Relay. A ativação F6 só entrega o proprietário da rota depois de ambos os condutores concluírem a prova.

A construção usa a identidade DOM e os termos autenticados daquela perna. Não cria clientes BTC/EVM para executar essa etapa DOM. O código mantém a distinção entre papel no transporte e índice criptográfico: a ordem inicial segue os papéis; a prova segue os IDs ordenados do roster. A primeira share revelada ainda exige a segunda mensagem, mesmo que a fase já se chame `SharesRevealed`.

O condutor executa uma mensagem local por chamada. Recupera primeiro o pedido DSC1 ou a mensagem assinada que já estejam persistidos, incluindo a interrupção anterior à entrega do último `0x0a`. A prova inicial de conhecimento da share é persistida antes da publicação de seu compromisso. O nonce, a rodada dois e a prova final usam o cofre criptográfico nativo. Não existe exportação da share secreta nem geração de um substituto durante a retomada.

A conclusão é revalidada pelo novo `completed_operational_bp_proof_v16`, no Store nativo. Ele audita o prefixo terminal imutável da prova mesmo se a sessão já avançou para outra fase; uma retomada não tenta executar novamente a prova sobre o estado de claim/refund.

O prazo de transporte dessas mensagens é persistido antes do primeiro envio: uma hora a partir da primeira chamada. Ele não altera prazos de settlement. Um prazo expirado continua causando recusa; não foi implementada renovação de envelope para essa sessão.

## Recuperação do cofre

`CollaborativeBpCustodyV16` distingue ausência autenticada, nonce existente, rodada dois e prova final. O cofre audita todos os registros e os respectivos envelopes criptográficos antes dessa classificação.

Dois estados intermediários têm recuperação explícita:

1. Rodada dois já persistida e nonce anterior ainda presente: aposenta o nonce e retoma a rodada dois.
2. Prova final já persistida e finalizador anterior ainda presente: exige o mesmo vínculo completo e os mesmos bytes de rodada dois, aposenta o finalizador e retoma a prova.

Prova final junto de nonce vivo, finalizadores incompatíveis, registros duplicados, corrupção e marcador terminal produzem erro. As operações nativas de criação e abertura do nonce também consultam essa classificação; o bloqueio não depende apenas do condutor do daemon.

Esses controles não provam resistência a toda forma de restauração conjunta de snapshots antigos. A proteção contra rollback continua dependendo das premissas e autoridades de armazenamento do projeto.

## Recebimento e espera por confirmação

O Relay pode renovar somente as autoridades reemitíveis previstas: early/BP e ingresso final do receptor. Uma tentativa incompatível preserva a autoridade anterior. Gates lineares de funding e de assinatura continuam exigindo retirada e consumo explícitos.

Para `0x12` antecipado, o Store verifica sessão, chain, identidade local, remetente, assinatura, sequência, transcript, template, transação nativa e abertura do ponto adaptor. Se a única etapa pendente for a observação canônica, retorna um estado próprio. O Relay não gera recibo de aceitação nem avança essa mensagem. O loop volta ao scanner e continua a outra perna e a recuperação. Assinatura inválida, evidência trocada, sessão incorreta ou Store corrompido continuam sendo erros.

Esta espera usa o inbox e o reassembler duráveis já existentes. Não cria outra fila nem extrai o segredo durante a verificação preliminar. A profundidade e a exposição durável continuam sendo responsabilidade do caminho nativo de observação.

## Testes adicionados

| Teste Rust | O que exercita |
|---|---|
| `v16_native_bp_reopens_and_reconciles_both_publication_crash_prefixes` | Cofres reais, compromisso/revelação idênticos após abertura, prova colaborativa completa, retomada nos dois estados intermediários e recusa de nonce consumido. |
| `v16_early_reveal_remains_bound_to_context_chain_roster_and_share` | Prova real, contextos trocados e mutações individuais dos bytes. |
| `v16_completed_f6_is_not_consumed_until_both_bootstrap_legs_finish` | F6 pronto aguarda a perna mais lenta. |
| `v16_shutdown_during_bootstrap_does_not_consume_ready_f6` | Parada preserva F6 e não avança mensagens. |
| `v16_only_native_verified_claim_wait_preserves_runtime_progress` | Somente a espera autenticada permite continuação; erros continuam distintos. |
| `v16_two_native_owners_complete_bp_with_restart_after_every_tick` | Cerimônia real, duas identidades, proprietários Contracts, Relay em disco e cofres reabertos a cada chamada até as 17 mensagens iniciais/BP. |

O último teste chama o mesmo condutor instalado no processo, mas não inicia duas instâncias do binário nem conecta chains. Não é prova de swap completo ou de funcionamento das 16 rotas. O teste de classificação de `0x12` também não substitui uma campanha completa de reorg/finality.

## Os seis blocos solicitados

| Bloco | Estado nesta V16 | O que ainda impede considerá-lo concluído |
|---|---|---|
| Bootstrap completo no binário | Parcial: early/BP agendado e retomável | Formação dos templates com carteiras dos participantes, refund/readiness e assinatura do funding. |
| F7, M.8 e claim no runtime | Parcial: melhora do receptor e da espera; componentes anteriores preservados | Montar e agendar o emissor, compor a share correta de gasto e consumir a saída M.8 no claim. |
| Compensação DOM segura e funcional | Pendente; recusa de funding XMR preservada | Condição de funding XMR executável pelo protocolo mesmo fora do daemon, mais o ciclo econômico completo. |
| DOM↔XMR completo | Pendente na composição operacional | Funding, sweep/refund, revelação e recuperação com compensação conectados aos proprietários reais. |
| Finality, Relay, crash e reorg | Parcial | Executar novos testes e construir/executar a campanha nativa completa de claim/reorg/recuperação. |
| Campanha econômica das 16 rotas | Pendente | Binários, chains de teste, casos econômicos e evidências reproduzíveis de cada rota. |

Uma compensação DOM plenamente assinada e incondicional ainda pode ser transmitida fora do daemon. Um `if` local ou uma observação RPC não corrige isso. Esta versão não remove a recusa protetora, não introduz um oráculo implícito e não apresenta a ausência de implementação como compensação funcional. A recusa foi deslocada para depois da ativação pública do bootstrap e antes da criação dos filhos de funding.

## Execução no Linux do operador

Na raiz `dom-protocol`:

```bash
# Regressões novas e tentativa de gerar o executável:
python3 crates/dom-interopd/scripts/test_daemon_v16.py --focus-v16

# Suíte de componentes/daemon e build completo:
python3 crates/dom-interopd/scripts/test_daemon_v16.py

# Somente compilação e publicação do ELF:
python3 scripts/build_daemon_v14.py --output dist/v16/dom-interopd --report-dir artifacts/daemon-v16-build
```

O nome V14 do construtor é preservado; ele compila os fontes presentes neste pacote. O script só publica o executável após o Cargo retornar sucesso e informar um artefato ELF. Pré-requisitos ausentes, compilação recusada e testes falhando ficam registrados separadamente. Nenhum desses comandos declara uma rota operacional apenas porque a matriz de configurações foi aceita.

O ZIP contém fontes cumulativos, branch local com alterações no índice Git, patch incremental, comparação byte a byte e evidências das verificações efetivamente realizadas. `STATUS-V16.json` registra as pendências; relatórios anteriores no repositório não são resultados desta versão.
