# V12 — preparar o funding XMR antes da admissão

O binário real agora oferece `prepare-xmr-funding-v12`. Ele solicita à carteira Monero uma transação assinada com `do_not_relay=true`, verifica os bytes localmente e publica um candidato privado. O comando nunca transmite a transação. O componente de funding recebe os mesmos bytes depois da admissão e só pode transmiti-los após verificar a autorização nativa de colateral DOM. A inicialização da rota XMR completa continua bloqueada pelos limites registrados em `docs/interop/hardening/V12-RISKS.md`; a preparação separada não remove esse bloqueio.

A preparação recebe a chave pública de gasto compartilhada e a chave privada de **visualização** da sessão. Não recebe share privada de gasto, chave de gasto completa, `T` ou `U`. O endereço de funding é derivado dessas chaves; o campo `destination` do setup XMR representa o destino final do sweep e não deve ser usado como endereço de funding.

## Compilar e consultar a ajuda

No Linux, na raiz do projeto:

```bash
cargo build --locked --release -p dom-interopd --no-default-features --features production
./target/release/dom-interopd prepare-xmr-funding-v12 --help
```

O comando exige o artefato de produção em release antes de ler a entrada privada. Ele não inicializa clientes, bancos ou signers BTC/EVM.

## Entrada privada

Uma única entrada JSON chega pelo stdin não interativo, seguida de EOF, com limite de 16.384 bytes. Campos desconhecidos ou repetidos, dois objetos concatenados, chaves de gasto, valores fora dos limites, escapes JSON e hex não canônico são recusados. Os campos dessa entrada não precisam de escapes; o escalar é lido diretamente de um buffer zeroizado com tamanho máximo pré-alocado.

Crie a área privada e o arquivo de configuração:

```bash
umask 077
mkdir -m 700 ./xmr-private
cat > ./xmr-private/request.private.json <<'JSON'
{
  "schema": "DOM-XMR-PRIVATE-FUNDING-V12",
  "wallet_rpc_url": "http://127.0.0.1:18083/",
  "network_tag": 2,
  "combined_spend_public_hex": "0000000000000000000000000000000000000000000000000000000000000000",
  "view_scalar_hex": "0000000000000000000000000000000000000000000000000000000000000000",
  "amount_piconero": 1000000000,
  "max_fee_piconero": 100000000,
  "account_index": 0,
  "subaddr_indices": [0],
  "priority": 0
}
JSON
```

**Os zeros são placeholders deliberadamente inválidos:** o comando os recusa antes de chamar a carteira. Substitua-os pelos parâmetros vinculados à sua sessão e ajuste os valores econômicos. A view key precisa ser um escalar canônico não zero, em little endian e 64 caracteres hex minúsculos. A chave pública de gasto também usa 64 caracteres hex minúsculos. As tags de rede são 1 para mainnet, 2 para stagenet e 3 para testnet.

O endpoint deve ser uma carteira de funding já aberta e isolada em loopback, com saldo desbloqueado no account/subaddresses escolhidos. Ela possui as próprias chaves de funding, distintas das shares do swap. Não há descoberta de carteiras ou seleção implícita de todos os subendereços. Para uma carteira com autenticação RPC, use o proxy local do operador que autentica a conexão ao backend; o cliente não aceita credenciais na URL. Redirecionamentos e proxies de ambiente são desativados.

Após configurar os parâmetros reais:

```bash
./target/release/dom-interopd prepare-xmr-funding-v12 \
  --output-dir "$(pwd)/xmr-private/candidate-001" \
  < ./xmr-private/request.private.json
```

A saída solicitada precisa estar ausente. Seu diretório pai deve existir, ser canônico, pertencer ao usuário atual e ter permissão `0700`.

## Resultado e ligação ao setup

Uma execução bem-sucedida publica `candidate-001/` com permissão `0700` e três arquivos `0600`:

- `funding-candidate.raw`: bytes privados da transação assinada; não publique nem transmita manualmente.
- `funding-public.json`: txid de consenso, fingerprint dos bytes, rede, endereço compartilhado, principal, fee, índice da saída e `broadcast: false`.
- `request-public.json`: parâmetros públicos da solicitação, sem view scalar, credenciais ou shares privadas.

O relatório público também é impresso em stdout. Use seu `funding_tx_hash` para vincular o setup XMR final **antes** de congelar/admitir os termos. A etapa de funding no runtime deve importar `funding-candidate.raw` e verificar novamente hash, endereço, quantidade e fee contra esses mesmos parâmetros. Preparar outra transação depois de fixar o txid muda a identidade e é recusado.

A verificação offline exige funding moderno CLSAG/Bulletproof+, exatamente uma saída para o endereço compartilhado com o principal exato, compromisso RingCT consistente, fee dentro do limite e ausência de timelock adicional. A presença na chain, a validade de consenso e a finalização continuam sendo verificadas pelo daemon/observer; o relatório privado não é prova de funding concluído.

## Interrupção e publicação durável

O comando grava e sincroniza o intento público em `candidate-001.preparing-v12/` **antes** da única chamada `transfer`. Ele não repete automaticamente a chamada após timeout ou resposta ambígua.

Os arquivos são criados exclusivamente, sincronizados e publicados por `renameat2(RENAME_NOREPLACE)`, seguido de sincronização do diretório pai. Nenhuma execução sobrescreve saída ou staging existente. Uma falha pode deixar o staging, ou uma publicação cuja confirmação final foi interrompida. Preserve e examine esses arquivos antes de uma nova preparação; não os apague para forçar retry. A simples ausência do diretório final não prova que a carteira deixou de assinar um candidato.

## Testes adicionados

```bash
cargo test --locked -p xmr-raw-tx-verify funding_v12
cargo test --locked -p xmr-rpc-broadcast-blocking private_funding_v12
cargo test --locked -p dom-interopd --no-default-features --features production production_xmr_funding_command_v12
```

Os testes cobrem ECDH/compromissos/quantidade, vetor de endereço upstream independente, resposta HTTP com identidade RPC trocada, entrada privada estrita, permissões, bytes preservados, symlink e publicação concorrente sem substituição. Os testes Rust foram escritos, mas não executados no ambiente de edição desta entrega, que não dispõe de Rust/Cargo.

Referências de implementação: [contrato RPC oficial `transfer`](https://docs.getmonero.org/rpc-library/wallet-rpc/#transfer) e [equações compactas RingCT no monero-oxide fixado](https://github.com/kayabaNerve/monero-oxide/blob/c8be5d3d1287669946a83fbfcb296ce2a8852e47/monero-oxide/wallet/src/lib.rs).
