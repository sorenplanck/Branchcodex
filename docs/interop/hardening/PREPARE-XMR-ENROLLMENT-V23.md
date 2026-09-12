# Custódia local XMR antes de F6

`prepare-xmr-enrollment-v23` prepara a parte secreta **local** de uma posição
XMR usando o SDK de produção. É uma operação off-line: não lê carteiras, não
chama RPC, não transmite transações e não altera a L1 DOM.

## Entradas públicas existentes

O diretório de estado precisa ser absoluto, canônico, do usuário atual e 0700.
O comando lê somente o manifesto V11 correspondente ao modo e suas referências
ao registro de implantação assinado, conjunto de autoridades do registro,
termos das duas posições, roster Relay e bundle de participantes. Esses arquivos
devem ser privados (0600), sem symlinks ou hardlinks.

Os pins do manifesto são confiança configurada pelo operador; não são uma
assinatura substituta das autoridades. O registro é verificado com suas
assinaturas reais. Os termos/roster/bundle são conferidos contra os pins, e as
duas DLEQs da posição selecionada são verificadas pelo SDK. O manifesto não
autoriza um papel arbitrário: o papel deriva do participante nos termos, e a
parte secreta precisa corresponder à chave pública daquele papel.

O bundle selecionado deve carregar enrollment nativo V23, não uma política
executável de refund legada. Não são necessários F6, TimeStore, RouteStore,
carteira DOM, sidecar ou os serviços de famílias não selecionadas. As referências
a esses recursos permanecem sujeitas à admissão completa do daemon depois.

## Criação

```sh
dom-interopd prepare-xmr-enrollment-v23 \
  --state-dir /caminho/privado/rota \
  --position upstream \
  --output-dir /caminho/privado/rota/custodia-xmr \
  < /caminho/privado/credenciais-enrollment.json
```

O diretório pai da saída deve existir e ser 0700; a saída e sua irmã
`custodia-xmr.preparing-v23` não podem existir. `downstream` seleciona a outra
posição, inclusive quando ambas usam a mesma família/rede.

O stdin aceita um único JSON de até 4096 bytes, seguido de EOF, sem campos
extras ou repetidos. A estrutura abaixo é ilustrativa: substitua os valores
entre `<...>` por credenciais reais fornecidas pelo seu processo de custódia,
sem colocá-las na linha de comando, logs ou histórico do shell.

```json
{
  "schema": "DOM-XMR-ENROLLMENT-V23",
  "local_participant_id": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
  "master_key_hex": "<64 caracteres hexadecimais minúsculos>",
  "spend_share_le_hex": "<parte local: 32 bytes little-endian em hex>",
  "view_key_le_hex": "<chave de visualização: 32 bytes little-endian em hex>"
}
```

O ID acima também é fictício: use o participante exato dos termos. Não envie a
parte secreta da contraparte nem a chave de spend combinada. Master, spend e
view devem ser não nulos e diferentes, como no preparador de inventário XMR.
Se usar um arquivo para stdin, mantenha-o 0600 sob diretório 0700; o comando
não remove nem faz backup desse arquivo. O buffer de leitura tem reserva única
limitada e é zerado ao terminar.

A saída publicada contém somente:

- `secrets.sqlite`: armazenamento criptografado do SDK;
- `nullifiers.sqlite`: registro durável contra reutilização do claim;
- `enrollment-public.json`: escopo, participante, papel e nomes dos arquivos.

Os bancos são fechados e reabertos pelo SDK antes da publicação. Arquivos 0600
e diretórios são sincronizados, e o diretório final é publicado com rename
atômico sem substituição. Falha ou crash pode deixar `.preparing-v23`; preserve
esse diretório para análise. Não existe reparo automático nem overwrite.

O bundle de autoridade XMR operacional deve referenciar esses arquivos pelos
campos existentes `secret_store` e `recovery_v23.nullifier_store`, com caminhos
relativos ao state-dir. A chave de armazenamento no stream V4 deve ser a mesma
master usada aqui. O comando não cria esse bundle nem os demais recursos de
recovery/sidecar e não concede autoridade ao seu relatório público.

## Reabertura

Use o mesmo comando com `--reopen` ao final. Envie somente `schema`,
`local_participant_id` e `master_key_hex`; não reenvie spend/view. O manifesto
`bootstrap-reopen-v11.conf` deve manter o escopo original. O registro histórico
fixado é revalidado, sem tratar a expiração posterior como nova admissão.

Banco ausente, schema incompleto, chave/papel/escopo trocado ou receipt divergente
causam recusa. Reopen não cria banco, schema, nonce ou partes secretas perdidas.

Isto fecha a preparação local desse par de bancos, **não** prova disponibilidade
da contraparte, assinatura de funding/claim, autorização F6, conclusão dos
12 artefatos ou prontidão de uma rota inteira para mainnet.

## Regressões

Os testes de biblioteca exercitam SQLite e DLEQs reais, ambas as partes locais,
recusas de chave/papel/escopo e estado incompleto. O positivo de subprocesso
requer o executável irmão construído pelo mesmo `cargo test --lib --tests`;
não faz build recursivo e falha se o binário estiver ausente. Os testes de
integração adicionais cobrem a interface e as recusas antes de qualquer escrita.
