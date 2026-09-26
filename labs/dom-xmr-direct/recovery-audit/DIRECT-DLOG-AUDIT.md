# Auditoria interna do candidato direto

Estado: argumento condicional e testes do laboratório; não auditoria independente,
não aprovação de depósito, não demonstração de swap atômico completo.

## O que o argumento de extração estabelece

Para Y=2, setup verificado e elementos invertíveis, a cifra é homomórfica em
mensagem e nonce inteiros. Duas respostas aceitas a bits opostos para o mesmo
compromisso implicam `C=Enc(d_m,d_r)` e `P=d_m*G`, com diferenças inteiras das
respostas. A abertura sequencial fornece `d_m mod N`. Os limites impostos
garantem `|d_m|<L_m<N/2`, portanto a decodificação assinada é única e seu escalar
módulo q corresponde ao ponto. Os dois componentes U/V e a equação de curva
são indispensáveis; reduzir a resposta inteira módulo q destrói esse argumento.

O modelo pequeno e os testes reais verificam instâncias dessa relação e
reproduzem falsificações quando se retiram as bordas. Isso não demonstra uma
análise completa de segurança do programa ou do hash. A implementação conserva
as equações individuais das 256 rodadas; não presume que agrupar equações em
grupos de ordem desconhecida tenha a mesma soundness.

Sob o modelo de oráculo aleatório, uma relação falsa não pode ter dois vetores
de desafio aceitos para o mesmo statement/compromissos: algum bit diferente
permitiria a extração acima. Isso motiva um limite de adivinhação por consulta
de 2^-256, mas a aplicação adaptativa/extração de conhecimento requer revisão
formal. Não converter o número de rodadas em segurança global: o módulo RSA
atual tem 2048 bits e a dureza temporal continua uma premissa separada.

## Privacidade: argumento de máscaras e obrigações

Para um bit fixo, um simulador algébrico pode escolher respostas e obter o
compromisso como `Enc(z_m,z_r)/C^c` e `z_m*G-c*P`. A distribuição real das
respostas é a distribuição das máscaras deslocada pelo witness quando c=1.
Para intervalos uniformes, a distância é limitada por
`m/B_m + r/B_r`; com os limites do produtor honesto, cada termo é <2^-256.
Somar os 256 limites dá <2^-247 para esse componente de um transcript de
desafios fixos. Isso é um argumento de deslocamento, não uma prova de NIZK
adaptativa ou de resistência a canais laterais.

Reutilizar máscaras em dois desafios permite extrair o segredo, como exige
a própria propriedade de extração. O produtor usa CSPRNG para cada prova;
resta especificar persistência, rollback e snapshots. `math/big` tem execução
variável e não se alega apagamento físico das cópias em memória. Encerrar o
processo do produtor demonstra separação do caminho de abertura, não erasure.

## Fronteiras implementadas

- Setup: o processo público confere a relação sequencial antes de reconhecer
  seus bytes. O produtor só divulga ciphertext/prova depois dessa resposta.
- Oferta: frames limitados a 2 MiB, um JSON por linha, campos desconhecidos e
  valores adicionais rejeitados. O corpo público recebe SHA-256 dos bytes
  exatos; Rust e Go conferem o mesmo binding. Isso não autentica uma rede.
- Statement: o verificador recebe contexto e ponto esperados do chamador;
  rejeita outro contexto, ponto, setup, elementos não invertíveis, pontos
  não canônicos ou fora do subgrupo primo e respostas fora dos limites.
- Abertura: somente após `ready`, um pedido com o binding exato resolve o
  puzzle. Encerramento exige EOF e contagem de uma abertura. EOF sem pedido
  cancela a sessão sem solve. O cliente espera término bem-sucedido.
- Rust: confere escalar canônico e seu ponto. `XmrDirectRecoveryLink` compara
  contexto e chave com o roster/papel antes de aceitar o vínculo da cápsula;
  na recuperação compara novamente roster, papel e binding, e restaura somente
  a share individual. O offset do output deve ser aplicado depois.

Ainda falta demonstrar esses controles em um transporte autenticado e em
estado durável. Os exemplos são locais, coordenados pelo mesmo teste, sem
adversário de rede. O modo `xmr-direct-recovery` já recuperou uma reserva de
moedas de teste em monerod isolado, incluiu a devolução e gastou seus dois
outputs em 52,027 s totais. Esse ensaio não usa admissão temporal nem exercita
a perna DOM; não demonstra atomicidade bilateral.

## O que falta para a meta de tempo e segurança

O experimento direto aceita dois perfis explícitos: T=200.000 e T=10.000.000.
O cliente envia sua escolha separadamente ao produtor e ao verificador, e
confere a resposta de ambos. Antes do trabalho sequencial, o verificador
rejeita T diferente de sua política local; escolher o perfil longo não permite
que o peer envie o curto. O parser rejeita valores negativos, excessivos ou
fora da lista. `verifiedDirectSetup` é separado do tipo anterior, cujo parser
continua limitado a 200.000. Os bytes completos do setup entram no desafio e
no binding da cápsula. Essa política limita trabalho e troca de parâmetros;
nenhum dos perfis constitui uma garantia de atraso ou admissão de fundos.

A verificação observada leva dezenas de segundos; a abertura do perfil curto
leva cerca de um segundo. Logo, não há janela útil demonstrada nesse perfil.
O relógio não pode começar de novo quando a verificação acaba. O campo
`offer_received_to_open_start_seconds` mede tempo desde a recepção completa
no cliente local: não é um instante autenticado de primeira divulgação.

Ao separar geração de saldo individual e depósito nativo na reserva, o ensaio
T=10.000.000 terminou em 131,917 s, com 17,423 s entre recepção e abertura e
48,179 s de solve local. Todos os custos continuaram no total, incluindo
maturação local do depósito. Essa diferença positiva não corrige as premissas
ausentes: não limita um adversário mais rápido, pausas honestas, disponibilidade
do material ou a divulgação por outro canal. O ensaio permanece sem DOM e sem
admissão temporal. Fonte: `../clsag-lab/XMR-DIRECT-TRANSFER-10M-REGTEST-RESULT.json`.

Precisamos estabelecer custos máximos e atraso mínimo sob premissas explícitas,
incluindo verificação, mensagens, pausas, restart e resolução nas cadeias. Depois
disso vem a composição da devolução XMR com claims concorrentes e a altura DOM
conservadora. A devolução financiada isolada já passou; nenhum teste isolado
aqui prova esse conjunto de requisitos.
