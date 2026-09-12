# Bundle operacional da posição XMR

`prepare-xmr-leg-v23` escreve o JSON canônico `XMR_ENROLLMENT_V23` aceito pelo
loader do daemon, junto com o digest que o manifesto V11 deve fixar. Usa o
encoder público `encode_xmr_enrollment_leg_authority_bundle_v23`; os fluxos de
exportação de teste também delegam a esse mesmo código de produção.

É configuração pública off-line, não uma assinatura nem uma admissão econômica.
O comando não lê/cria carteira, chave, sidecar, banco de custódia ou candidato de
funding. Não faz RPC, broadcast, implantação ou alteração de L1.

## O que já precisa existir

O mesmo contexto público usado por
[prepare-xmr-enrollment-v23](PREPARE-XMR-ENROLLMENT-V23.md): manifesto V11 de
criação, registro assinado e suas autoridades, termos, roster e bundle de
participantes com as duas DLEQs da posição. O comando revalida esses documentos
pelos pins existentes, sem precisar de F6, TimeStore ou RouteStore.

Também é obrigatória a política canônica de compensação/disponibilidade
**realmente negociada**. Seu hash precisa ser o `assurance_policy_hash` dos
termos. Nenhuma política ou disponibilidade padrão é criada. Política antiga,
de outra sessão ou sem a disponibilidade limitada V23 é recusada.

## Entrada pública e comando

O stdin recebe um JSON único de até 16384 bytes, seguido de EOF:

- `schema`: `DOM-XMR-LEG-V23`;
- `compensation_policy`: array dos bytes canônicos da política negociada;
- `resources`: objeto abaixo, sem credenciais ou campos adicionais.

Exemplo de `recursos-xmr.json` para quem recebe XMR no claim. Os IDs são
ilustrativos; devem ser substituídos pelos IDs exatos do participante e da
custódia independente. Os caminhos são relativos ao diretório de estado.

```json
{
  "local_participant_id": [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],
  "secret_store": "custodia-xmr/secrets.sqlite",
  "nullifier_store": "custodia-xmr/nullifiers.sqlite",
  "sidecar_socket": "servicos/xmr.sock",
  "sidecar_timeout_ms": 1000,
  "custody_directory": "arquivo-grafo-xmr",
  "sealing_key_file": "chaves/arquivo-xmr.key",
  "custody_id": [2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2]
}
```

`custody_directory` é um nome único no nível raiz para o **arquivo do grafo**;
não é o diretório que contém os bancos de enrollment. Os recursos não podem
coincidir nem ser ancestrais uns dos outros. `sealing_key_file` é somente uma
referência à chave independente: nunca envie a chave em si neste JSON.

Somente o participante que fornece XMR precisa acrescentar:

```json
"private_funding": {
  "raw_transaction_file": "funding-xmr/funding-candidate.raw",
  "max_fee_piconero": 3
}
```

A taxa acima é apenas ilustrativa. Deve ser positiva e respeitar os termos.
Esse campo é obrigatório para o funder XMR e proibido para o claim receiver.
O candidato deve ter sido preparado separadamente; o comando não o abre.

Se a política já estiver num arquivo binário canônico, `od` e `jq` podem montar
a solicitação pública sem reescrever manualmente o array de bytes:

```sh
od -An -v -tu1 politica-compensacao.v23 |
  jq -s --slurpfile recursos recursos-xmr.json \
    '{schema:"DOM-XMR-LEG-V23", compensation_policy:., resources:$recursos[0]}' |
  dom-interopd prepare-xmr-leg-v23 \
    --state-dir /caminho/privado/rota \
    --position upstream \
    --output-file /caminho/privado/rota/inputs/upstream-authority.v11
```

O diretório de estado e o pai da saída devem ser canônicos, do usuário atual e
0700. A saída é um arquivo novo 0600, publicado por staging sincronizado e
rename atômico sem overwrite. Saída ou `.preparing-v23` existente causa recusa;
preserve publicações interrompidas para inspeção.

O stdout contém somente `schema`, `authority_bundle_digest` (hexadecimal),
`bytes` e `network_access:false`. Fixe esse digest e o caminho relativo da saída
no descritor da posição no manifesto definitivo. O comando **não modifica** o
manifesto nem toma o digest previamente declarado do bundle como autorização
para escrever outro arquivo.

## Limites da entrega

O bundle não carrega `scope`, uma política admitida, template refund legado,
assinatura ou prova de disponibilidade remota. O loader real continua responsável
por registry/admissão econômica, correspondência entre posição e sessão e
abertura/verificação dos recursos reais.

Um bundle publicado não implica sidecar funcionando, arquivo de recovery
provisionado, funding autorizado, 12 artefatos concluídos ou rota inteira pronta
para mainnet. O ganho concreto é que o operador já consegue produzir os bytes
exatos desse artefato fora de um harness `cfg(test)`.
