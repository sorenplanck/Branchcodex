# Provedor externo da chave de wrapping DXA1

O `arbiter_party` aceita duas origens para a chave que cifra sua share XMR:

- um caminho simples ou `file:/caminho`, que mantém o formato local existente;
- `unix:/caminho/absoluto.sock`, que consulta um agente externo a cada criação
  ou restauração do processo.

O segundo modo permite que um agente de secrets, KMS ou HSM controle a política
e a persistência da chave. Nenhuma chave é colocada na linha de comando, no
ambiente ou no filesystem do participante. O socket precisa ser Unix stream,
ter caminho absoluto e modo exato `0600`. Conexão, escrita e leitura têm limite
de cinco segundos.

## Protocolo binário v1

O participante abre uma conexão por solicitação, escreve os campos abaixo sem
prefixo de tamanho e fecha o lado de escrita:

| Campo | Tamanho | Valor |
| --- | ---: | --- |
| magic | 29 bytes | ASCII `DXA1/key-provider/request/v1` seguido de NUL |
| role | 1 byte | `1` para dono DOM, `2` para dono XMR |
| settlement id | 32 bytes | identificador exato da operação |
| context hash | 32 bytes | contexto exato da operação |
| chain id | 32 bytes | rede DOM canônica |
| state exists | 1 byte | `0` para criação, `1` para restauração |

O provedor autoriza a combinação inteira e responde uma vez:

| Campo | Tamanho | Valor |
| --- | ---: | --- |
| magic | 30 bytes | ASCII `DXA1/key-provider/response/v1` seguido de NUL |
| request digest | 32 bytes | SHA-256 de toda a solicitação recebida |
| wrapping key | 32 bytes | chave XChaCha20-Poly1305 estável para esse binding |

Tamanho diferente, digest de outra solicitação, socket inseguro, timeout ou
chave errada fazem o participante falhar antes de ficar pronto. Na restauração,
a chave precisa ser a mesma; a autenticação AEAD do estado verifica isso.

O provedor deve registrar de forma durável que já autorizou a criação de um
binding e recusar posteriormente `state exists = 0` para o mesmo binding. Essa
política impede que a perda do arquivo cifrado seja tratada como uma operação
nova. Também deve entregar chaves diferentes para bindings diferentes e limitar
o acesso ao UID isolado do participante.

## Limite de segurança

Este protocolo remove a chave persistente do disco e dos backups do
participante. A chave e a share descriptografada ainda existem por instantes na
memória do `arbiter_party`, porque ele executa as operações criptográficas XMR.
Um host privilegiado capaz de ler essa memória continua fora do modelo. Para
defesa contra o administrador do host, o signer inteiro precisa executar dentro
do HSM, enclave ou host isolado; apenas mover o armazenamento da chave para um
KMS não basta.

O teste `scripts/test_arbiter_party_state.py` cobre criação, restauração,
binding da requisição, chave errada, resposta cruzada, socket ausente, symlink,
permissão insegura e timeout. O ensaio de três contêineres usa dois provedores
externos, reinicia os participantes e confirma que nenhum arquivo local de
wrapping foi criado.
