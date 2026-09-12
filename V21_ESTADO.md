# V21 — claim F7 conectado ao executor DOM

Base imediata: V20 corrigida, commit local `f6365e75958197ef46dc16218996a7d68df75617`.
Branch local: `interop/v21-f7-claim-execution`.
SHA-256 do ZIP base: `b5dd50c9cf4cbad092bc987eb4d7969b953c4ecbfb17418fa9a9de4359b9bd1a`.

## Código acrescentado

- Dono privado compartilhado entre o assinador F7 e o filho DOM, utilizando o mesmo Store, a share e o vault do bootstrap.
- Adaptação do claim chamada pela materialização do coordenador, depois da validação do escopo e de nova observação das âncoras. O relógio é atualizado depois do RPC, antes da exposição.
- Carregamento privado do segredo original para o emissor downstream LocalOrigin dos perfis nativos EVM/SOL. O scalar deve abrir o ponto já congelado na composição assinada; não é gerado um substituto.
- Exposição persistida antes do plano do filho e da transmissão. Compromisso do dono da preparação gravado atomicamente no journal existente; recuperação do preparo pelo mesmo dono após reinício.
- Executor DOM seleciona a autoridade F7, retoma os bytes exatos, transmite pelo cliente DOM existente e persiste a admissão. Admissão já persistida permite reparar o registro local sem retransmitir.
- Handoff da admissão nativa à solicitação 0x12, assinatura pela mesma identidade e staging pelo mesmo Relay. Mensagens anteriores pendentes não são classificadas como claim entregue.
- Reextração pública pelo emissor após admissão durável, com nova prova da transação canônica, txid exato, template, assinatura e confirmações. O emissor não fabrica observação de receptor.
- Refund nativo bloqueado também pela existência da exposição persistida quando o cabeçalho ainda não avançou após um crash.
- Regressões escritas para recuperação de preparo, mesmo dono, outro dono, outra evidência, idempotência e corrupção versus indisponibilidade. Não executadas nesta sessão.

## Caminho conectado na fonte

Runtime universal → Stage-12 → rodada F7 → dono V21 → materialização do filho DOM → adaptação/exposição V14 → executor DOM → envio/admissão → 0x12 pela identidade/Relay → observação de finalidade e reextração pública.

O incremento alcança o claim DOM dos perfis EVM/SOL montados pelo agendador F7. Não transforma uma autorização Bitcoin M.8 em F7 nem concede autorização para funding XMR sem recuperação válida.

## Preparar no seu ambiente

Preserve os clientes e configurações usados na V20. Extraia o código em uma nova pasta e mantenha estado e segredos fora da árvore do projeto.

Somente o participante emissor downstream de primeira revelação precisa provisionar o scalar ORIGINAL que foi usado nos termos assinados:

```bash
python3 scripts/provision-local-origin-v21.py --state-dir /caminho/absoluto/do/estado-da-rota
```

O utilitário solicita 64 dígitos hexadecimais sem eco e cria `production-local-origin-secret.v21` com os 32 bytes big-endian, modo 0600. Não sobrescreve arquivo existente. O diretório deve pertencer ao usuário atual e ter modo 0700. O daemon verifica o ponto e o papel antes de permitir avanço. Um scalar aleatório novo não serve para termos já assinados.

Receptores não precisam desse arquivo. Reinício após exposição nativa persistida também não precisa dele. A cópia privada no disco permanece sob controle do operador; a cópia em memória é descartada após persistência.

Na raiz `dom-protocol`, para compilar:

```bash
bash scripts/build-v21.sh
```

O script chama `cargo build --locked --release -p dom-interopd --bin dom-interopd --no-default-features --features production`. Com a saída padrão do Cargo, o executável será `target/release/dom-interopd`. Use os mesmos argumentos de produção/configuração da V20. O script não inicia serviços nem realiza transferências.

## Estado e limites

Nenhum build, teste Rust, script do projeto, daemon ou swap foi executado aqui. A entrega contém fonte e scripts, não um executável compilado nesta sessão. Foram conferidas a fonte, as chamadas e a continuidade dos arquivos do pacote.

Ainda faltam o consumo integral do resultado Bitcoin M.8 pelo runtime e a compensação XMR executável condicionada ao funding, com o fechamento da execução/recuperação correspondente. As recusas desses caminhos permanecem. **As 16 rotas não estão concluídas; esta entrega não declara nota 10/10 ou prontidão operacional.**

Validação pelo operador: compilar com a feature production; executar os testes novos e suas suítes anteriores; exercitar claim e 0x12; interromper entre preparo, exposição, tentativa, admissão e staging; confirmar recuperação com o mesmo txid; rejeitar txid trocado, outra chain, outro dono e segredo incompatível; confirmar que ausência legítima e indisponibilidade não viram aprovação.

Os arquivos V19/V20 mantidos no pacote descrevem versões anteriores. A V21 continua integralmente a V20 corrigida. Os commits são locais derivados dos ZIPs; não houve push, PR ou implantação.
