# Drill de restauração em máquina externa

Este procedimento produz uma atestação assinada de que bytes **inteiramente
sintéticos**, criados na máquina A, foram autenticados e restaurados na máquina
B. Ele é um gate manual de release; não é um backup de credenciais reais e não
autoriza seu uso.

O fluxo tem três etapas:

1. **A / `prepare`:** cria o request, o payload sintético e a assinatura da
   chave solicitante;
2. **B / `run`:** valida o request contra um checkout independente do mesmo
   commit, comprova que `source.tar` é byte-exato a ele, compila o archive,
   exercita os bytes vindos de A e assina somente o resultado fechado;
3. **A / `check`:** valida todos os vínculos e a assinatura de B, consome o
   nonce e emite um receipt contrassinado.

Todos os três comandos exigem stdin, stdout, stderr e terminal controlador
reais e recusam ambientes comuns de CI. Um teste unitário do parser no CI pode
detectar regressões, mas **nunca** satisfaz este gate humano e externo.

## Pré-condições e modelo de confiança

- A e B devem ser computadores e armazenamentos distintos. Uma VM ou um
  container executado no host A não conta como B.
- B deve obter um clone independente do repositório. Não execute o launcher
  extraído de `payload/source.tar` nem copie a árvore de trabalho de A.
- Os checkouts de A e B devem estar limpos e no mesmo commit e tree. O protocolo
  também compara `source.tar`, byte a byte, com um archive regenerado no clone
  de B.
- São necessárias duas chaves Ed25519 diferentes: a chave solicitante A e uma
  chave atestadora exclusiva de B. Nenhuma chave privada é transferida.
- O source assinado é tratado como código confiável, não como entrada hostil.
  O runner não é uma sandbox para código malicioso executado sob o mesmo UID.
- Cada host deve receber a chave **pública** do outro por um canal autenticado e
  fora do request/result. Uma chave incluída no mesmo bundle que sua assinatura
  não é uma âncora de confiança.
- Use apenas dados sintéticos. O request contém uma senha mestra e recovery
  sintéticos para que B possa exercitar os mesmos bytes produzidos em A.

As dependências de build e teste do PVault, Python 3, Git, OpenSSH, CMake e
Ninja precisam estar instalados nos dois hosts.

As assinaturas OpenSSH usam namespaces separados para impedir que um documento
de uma etapa seja aceito em outra:

- `pvault-external-restore-request-v1` para o request de A;
- `pvault-external-restore-result-v1` para o resultado de B;
- `pvault-external-restore-receipt-v1` para o receipt de A.

## Chaves e fingerprints fora de banda

Se A já usa `~/.ssh/pvault_signing`, pode reutilizar essa chave como
solicitante. Caso contrário, gere uma chave em A:

```sh
install -d -m 0700 "$HOME/.ssh"
ssh-keygen -t ed25519 -f "$HOME/.ssh/pvault_signing" \
  -C "PVault external restore requester A"
```

Gere em B uma chave dedicada, que não deve existir em A nem ser usada para
outra finalidade:

```sh
install -d -m 0700 "$HOME/.ssh"
ssh-keygen -t ed25519 -f "$HOME/.ssh/pvault_external_attestor" \
  -C "PVault external restore attestor B"
```

Mantenha cada chave privada com modo `0600`. Copie somente os arquivos `.pub`
para um diretório de confiança privado no outro host e compare seus fingerprints
por um canal autenticado independente, por exemplo presencialmente, por chamada
de voz previamente reconhecida ou por outro canal já verificado:

```sh
install -d -m 0700 "$HOME/.local/share/pvault-trust"
install -m 0600 /midia-ou-canal-autenticado/chave-do-outro-host.pub \
  "$HOME/.local/share/pvault-trust/chave-do-outro-host.pub"
ssh-keygen -lf "$HOME/.local/share/pvault-trust/chave-do-outro-host.pub"
```

Envie também de A para B, fora do bundle, o identificador exato mostrado por
`git rev-parse HEAD`. B deve confirmar esse valor antes de executar qualquer
código do protocolo.

## 1. Máquina A: preparar e assinar o request

Use uma árvore limpa no commit que será atestado. Carregue somente a chave A
no agente usado para a assinatura:

```sh
cd "$HOME/pvault"
git status --short
git rev-parse HEAD
ssh-add "$HOME/.ssh/pvault_signing"

install -d -m 0700 "$HOME/pvault-external"
./scripts/external-restore-prepare.sh \
  --output "$HOME/pvault-external/request-a-b" \
  --requester-key "$HOME/.ssh/pvault_signing.pub" \
  --attestor-pub "$HOME/.local/share/pvault-trust/host-b-attestor.pub" \
  --expires-hours 72
```

O diretório indicado por `--output` não pode existir, deve ficar fora do
repositório e seu diretório pai deve pertencer ao usuário e não ser gravável por
grupo/outros. O protocolo pede uma frase dinâmica no terminal e cria:

```text
request-a-b/                         0700
  request.json                       0600
  request.json.sig                   0600
  payload/                           0700
    active-mutated.pvlt              0600
    backup.pvlt                      0600
    fixture-summary.json             0600
    master-password.bin              0600
    recovery.pvault-recovery         0600
    source.tar                       0600
```

O request usa por padrão validade de 72 horas. `--expires-hours` aceita de 1 a
168 horas. Planeje tempo suficiente para executar B e aceitar o resultado em A;
um resultado não pode ser aceito depois da expiração.

## Transferir A → B

Transfira `request-a-b` por mídia removível criptografada ou por transporte
autenticado, preservando os modos. Por exemplo, sobre uma conexão SSH cuja
host key já foi verificada:

```sh
rsync -a --chmod=D700,F600 \
  "$HOME/pvault-external/request-a-b" \
  usuario@host-b:"pvault-external/"
```

Não coloque as chaves públicas confiáveis dentro desse diretório: o parser
exige uma lista exata de entradas, e a autenticidade das chaves deve vir de
fora do bundle. Mesmo contendo somente canários, trate o request como material
privado e não o envie para issues, CI, logs ou artefatos públicos.

## 2. Máquina B: executar em clone independente

Em B, clone o repositório por uma origem independente e selecione o commit
informado por A fora de banda. O checkout deve permanecer destacado e limpo:

```sh
git clone https://github.com/EduardoPaim5/pvault.git \
  "$HOME/src/pvault-external-restore"
cd "$HOME/src/pvault-external-restore"
git checkout --detach COMMIT_EXATO_INFORMADO_POR_A
git status --short
git rev-parse HEAD
```

Antes do exercício, a chave privada B **não pode estar carregada em agente
algum acessível ao processo**. Inicie o wrapper removendo explicitamente as
variáveis de agente herdadas:

```sh
install -d -m 0700 "$HOME/pvault-external/results"
env -u SSH_AUTH_SOCK -u SSH_AGENT_PID \
  ./scripts/external-restore-run.sh \
  --request "$HOME/pvault-external/request-a-b" \
  --result "$HOME/pvault-external/results/result-b-a" \
  --requester-pub "$HOME/.local/share/pvault-trust/host-a-requester.pub" \
  --attestor-key "$HOME/.ssh/pvault_external_attestor.pub"
```

Apesar do nome da opção `--attestor-key`, ela recebe o arquivo **público**
`.pub`. O wrapper valida assinatura, fingerprints, commit/tree, archive,
validade, commitment e replay antes de exercitar cópias privadas do payload.

Depois que build, drill local, autenticações e restauração terminarem, o
wrapper confirma que nenhum processo mantém o workspace aberto e cria um
`ssh-agent` dedicado e efêmero. Ele então exibe o caminho exato do socket. Só
nesse momento, em outro terminal de B, carregue a chave privada no agente
mostrado, substituindo o caminho pelo valor impresso:

```sh
env -u SSH_AGENT_PID \
  SSH_AUTH_SOCK='/caminho/exato/attestor-agent.sock' \
  ssh-add "$HOME/.ssh/pvault_external_attestor"
```

Volte ao primeiro terminal e digite a frase dinâmica solicitada. O agente
dedicado é encerrado ao final da assinatura. Não carregue a chave antes do
prompt e não substitua esse agente por um agente persistente da sessão.
Preferencialmente mantenha a chave B em hardware com confirmação física ou em
mídia removível/desmontada durante o exercício, inserindo-a somente nesse
momento pós-teste.

Um sucesso publica somente:

```text
result-b-a/                           0700
  result.json                         0600
  result.json.sig                     0600
```

Vaults, recovery, evidências intermediárias e logs não fazem parte do
resultado e não devem voltar para A.

## Transferir B → A

Retorne **somente** `result.json` e `result.json.sig`, preservando o diretório
`0700` e os arquivos `0600`. Use uma mídia/rota autenticada separada ou, por
exemplo:

```sh
rsync -a --chmod=D700,F600 \
  "$HOME/pvault-external/results/result-b-a" \
  usuario@host-a:"pvault-external/"
```

A assinatura de B protege a integridade e a origem do resultado, mas A ainda
deve usar a cópia da chave pública B que foi autenticada fora de banda.

## 3. Máquina A: validar, consumir e contrassinar

De volta ao clone original limpo em A, mantenha a chave solicitante carregada
no agente e execute:

```sh
cd "$HOME/pvault"
./scripts/external-restore-check-result.sh \
  --request "$HOME/pvault-external/request-a-b" \
  --result "$HOME/pvault-external/result-b-a" \
  --requester-key "$HOME/.ssh/pvault_signing.pub" \
  --attestor-pub "$HOME/.local/share/pvault-trust/host-b-attestor.pub" \
  --receipt "$HOME/pvault-external/receipt-a-b"
```

O diretório de receipt também deve ser novo, privado e externo ao repositório.
Após a frase dinâmica, o comando verifica novamente request e result, compara os
hashes com os bytes originais, exige todos os checks verdadeiros, assina o
receipt e consome atomicamente o nonce. Preserve o receipt junto dos registros
da release; ele não contém credenciais nem os vaults sintéticos.

## Estado, expiração e replay

O estado local fica em
`$XDG_STATE_HOME/pvault/external-restore/` ou, na ausência de
`XDG_STATE_HOME`, em `~/.local/state/pvault/external-restore/`, sempre em
diretórios `0700` e arquivos `0600`:

- A grava `pending/<nonce>/` depois de publicar e assinar o request;
- B reserva `used/<nonce>/` **antes** do exercício. Uma falha posterior ainda
  queima o nonce e impede nova tentativa naquele host;
- A move atomicamente `pending/<nonce>/` para `consumed/<nonce>/` ao aceitar e
  assinar o receipt.

Requests repetidos, nonces já usados/consumidos, resultado fora da janela e
commitments iguais falham fechados. Há tolerância de cinco minutos apenas para
clock skew no início da janela. Se B falhar depois de reservar o nonce, se o
request expirar ou se A não conseguir aceitá-lo a tempo, crie um request novo;
não edite JSON, assinaturas ou ledgers para reaproveitar a tentativa.

## O que o receipt sustenta

Quando as três etapas passam, request, result e receipt sustentam que:

- duas chaves Ed25519 distintas assinaram namespaces distintos de request,
  result e receipt;
- B declarou operar em outra máquina e outro armazenamento, fora de VM ou
  container hospedado em A, com chave atestadora exclusiva;
- os commitments derivados de `/etc/machine-id` e do nonce diferem sem publicar
  o machine-id bruto;
- B usou um checkout limpo no commit/tree assinados e regenerou `source.tar`
  byte a byte;
- o código foi compilado em B e o drill local passou;
- senha e recovery sintéticas autenticaram os bytes originados em A;
- o estado anterior ao restore coincide byte a byte com
  `active-mutated.pvlt`, e o estado final coincide byte a byte com `backup.pvlt`;
- a semântica esperada é preservada e os inputs transferidos não foram
  modificados;
- o resultado fechado não contém os canários secretos conhecidos pelo
  protocolo.

## Limites honestos

O protocolo **não prova criptograficamente** que A e B são hardwares físicos
distintos. A separação é uma declaração do operador, reforçada por chaves
distintas e commitments salgados pelo nonce. `/etc/machine-id` pode ser
clonado, alterado ou virtualizado.

Ele também não constitui auditoria independente, não testa credenciais reais,
não prova apagamento de dados, não substitui backups offline periódicos e não
garante recuperação diante de toda falha de mídia, kernel, hardware ou operador.
O agente efêmero evita exposição acidental da chave via ambiente aos processos
de build/teste, mas não cria isolamento contra source hostil sob o mesmo UID:
modo `0600` não impede esse UID de ler/copiar uma chave privada em disco, e um
daemon malicioso poderia abandonar o workspace antes da verificação. Para essa
fronteira, use outro UID/ambiente realmente isolado e uma chave hardware-backed
ou fisicamente ausente durante o exercício. O receipt declara explicitamente
que o source foi tratado como confiável.
Um PASS fecha apenas o gate operacional desta revisão e deste ambiente. A
decisão de permitir credenciais reais continua condicionada aos demais gates
de auditoria, compatibilidade, release assinada e recuperação definidos no
roadmap.
