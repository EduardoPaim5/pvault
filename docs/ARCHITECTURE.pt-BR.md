# Arquitetura do PVault

## 1. Estado e objetivo

O PVault é um gerenciador de senhas pessoal, local-first, escrito em C11 para
Linux e operado por CLI. A versão atual implementa o núcleo desktop. Android e
sincronização permanecem fora do binário 0.1 até o formato, a recuperação e o
comportamento sob falhas receberem uso prolongado e auditoria independente.

O estado continua pre-alpha, sem auditoria independente. Esta arquitetura
descreve propriedades pretendidas e implementadas, não autoriza armazenar
credenciais reais nem usar o PVault como única cópia de dados importantes.

O projeto é GPL-3.0-or-later. Código aberto permite inspeção, builds
reprodutíveis e auditorias, mas não substitui uma auditoria de segurança.

## 2. Limites e princípios

- O cofre fechado deve resistir a cópia, modificação e truncamento do arquivo.
- Nenhum segredo ou seletor de registro é aceito por argumento, variável de
  ambiente ou arquivo temporário em texto claro.
- Senhas não são exibidas pela interface normal; a recuperação usual usa um
  clipboard de curta duração.
- Metadados descriptografados não são enviados por padrão a stdout
  redirecionado; uma exceção exige `--allow-redirect` explícito.
- Falhar ao bloquear uma região secreta na RAM é erro fatal, sem downgrade.
- Escritas preservam o snapshot anterior e detectam escritores obsoletos.
- Root, kernel comprometido, keylogger, terminal malicioso e display server
  hostil não estão dentro do limite de proteção.

O modelo completo está em [THREAT_MODEL.md](../THREAT_MODEL.md), e o formato
normativo está em [FORMAT.md](FORMAT.md).

## 3. Componentes desktop

```text
pvault CLI / shell / picker
        |
        +-- entrada segura em /dev/tty
        +-- gate de stdout para metadados descriptografados
        +-- supervisor pvault-clip -- xclip ou wl-copy
        |
        v
modelo em arena segura (records, strings, VMK)
        |
        +-- codec CBOR determinístico
        +-- Argon2id + XChaCha20-Poly1305 (libsodium)
        |
        v
arquivo .pvlt + lockfile + backups criptografados
```

Os módulos de codec, criptografia e modelo não dependem de ncurses, rofi ou
clipboard. Por conveniência, o target desktop `pvault_core` ainda agrega store,
TTY hardening e configuração XDG específicos de Linux. A fase Android deve
extrair uma interface de plataforma antes de reutilizar os módulos portáveis
via NDK; o target atual não deve ser compilado no Android sem essa separação.

## 4. Hierarquia criptográfica

Na criação são gerados aleatoriamente:

- `vault_id`: identidade pública autenticada do cofre;
- `device_id`: identidade do escritor dentro do payload;
- VMK: chave mestra aleatória de 256 bits;
- recovery key: segredo independente de 256 bits.

A senha mestra passa por Argon2id13 (`opslimit=3`, `memlimit=256 MiB`) e produz
uma KEK que cifra a VMK. A recovery key deriva outra KEK com contexto
`PVRECV01`. A VMK deriva a chave do corpo com contexto `PVBODY01`. Keyslots e
corpo usam XChaCha20-Poly1305, sempre com nonces novos. O header serializado é
AAD do corpo, vinculando algoritmos, keyslots, nonce e tamanho ao ciphertext.

A senha não cifra diretamente os registros. Por isso é possível trocar senha
ou recovery key sem mudar a identidade de longo prazo do cofre.

## 5. Estruturas e serialização

As estruturas abaixo representam o modelo em RAM; elas nunca são gravadas com
`fwrite(struct)`. O codec codifica cada inteiro explicitamente e o payload usa
CBOR determinístico.

```c
typedef struct {
    uint64_t opslimit;
    uint64_t memlimit;
    uint8_t salt[16];
    uint8_t nonce[24];
    uint8_t wrapped_vmk[48];
} pv_keyslot_password;

typedef struct {
    uint8_t nonce[24];
    uint8_t wrapped_vmk[48];
} pv_keyslot_recovery;

typedef struct {
    uint8_t magic[8];
    uint16_t major, minor;
    uint32_t header_len, flags;
    uint8_t vault_id[16];
    uint16_t kdf_id, wrap_aead_id, body_aead_id, slot_count;
    pv_keyslot_password password_slot;
    pv_keyslot_recovery recovery_slot;
    uint8_t body_nonce[24];
    uint64_t body_ciphertext_len;
} pv_file_header;

typedef struct {
    uint8_t id[16];
    uint64_t revision;
    int64_t created_ms, updated_ms;
    uint32_t flags;
    pv_slice title, username, password, notes;
    pv_slice *urls, *tags;
    pv_custom_field *fields;
    size_t url_count, tag_count, field_count;
} pv_record;
```

O arquivo contém um header fixo de 252 bytes e um ciphertext autenticado. O
plaintext do corpo é `le32(cbor_len) || CBOR || padding aleatório`, arredondado
para múltiplos de 4096 bytes. O parser rejeita comprimentos não canônicos,
flags desconhecidas, UTF-8 inválido, IDs zerados/duplicados, trailing data e
qualquer divergência dos limites documentados.

## 6. Ciclo de vida da memória ao ler uma senha

1. Antes da descriptografia, o processo desabilita core dumps e `ptrace`
   ordinário com `RLIMIT_CORE=0` e `PR_SET_DUMPABLE=0`.
2. A senha é lida de `/dev/tty`, com echo desabilitado, para memória criada por
   `sodium_malloc` e obrigatoriamente bloqueada por `sodium_mlock`.
3. Argon2id deriva a KEK em outra região segura. A senha é liberada logo após o
   unlock; `sodium_free` zera e desbloqueia a região (equivalente ao ciclo
   `explicit_bzero` + `munlock` + `free`, sem permitir que o compilador remova a
   limpeza).
4. A VMK e chaves derivadas ficam em regiões seguras separadas. O ciphertext é
   normal, mas o plaintext descriptografado e a arena de registros são
   page-locked.
5. O CBOR só é exposto ao modelo depois da autenticação AEAD e de toda a
   validação estrutural e semântica. A arena passa para read-only com
   `sodium_mprotect_readonly`.
6. Para copiar uma senha, apenas o slice selecionado atravessa um pipe anônimo
   para o owner do clipboard. Ao terminar a operação, plaintext, VMK e buffers
   intermediários são zerados e liberados.

`mlock` reduz exposição ao swap comum; não protege contra root, hibernação não
criptografada, DMA, registradores ou um processo já comprometido.

## 7. Contrato da CLI e metadados

`edit`, `remove`, `show` e `copy` não recebem consulta posicional. Cada comando
abre o picker interno em `/dev/tty`, de modo que título, username, URL, tag e ID
persistente não precisem entrar em `argv`, `/proc/<pid>/cmdline` ou histórico
normal do shell. As formas pre-alpha antigas com `QUERY` são recusadas com erro
de uso; essa quebra é deliberada e não há fallback silencioso. A recusa não
apaga um argumento que já tenha sido entregue ao shell e ao kernel, portanto
testes da sintaxe legada devem usar somente dados sintéticos.

`list`, `show` e `pick` sem `--copy` recusam stdout que não seja terminal. O
mesmo gate protege a identidade autenticada emitida por `rescue verify`. A flag
`--allow-redirect` libera conscientemente essa saída, mas não cifra o destino,
não corrige permissões e não impede logs ou retenção por consumidores
posteriores. `shell` exige stdin e stdout terminais. Mensagens de sucesso de
`add` e `edit` são genéricas e não contêm ID.

Em `copy`, `--field password|username|url` só escolhe categorias genéricas.
`--field custom` lista nomes sanitizados em `/dev/tty` e pede um índice privado;
assim, duplicatas permanecem selecionáveis e nomes arbitrários não entram em
argumentos. O picker interno permanece o
padrão. Rofi é opt-in e recebe título sanitizado mais um token aleatório efêmero
por invocação, nunca `record.id`. O processo rofi é iniciado com allowlist de
variáveis de display, runtime, autenticação, home e locale. Mesmo assim, ele é
externo ao núcleo confiável e observa os títulos exibidos.

## 8. Persistência, concorrência e recuperação

- Um lockfile estável serializa escritores.
- O hash do snapshot aberto impede que um processo antigo sobrescreva uma
  versão mais nova.
- O novo arquivo é criado no mesmo diretório, escrito, sincronizado e renomeado
  atomicamente; depois o diretório é sincronizado.
- Antes da troca, o snapshot anterior vira backup criptografado. Restore cria
  também um backup pre-restore.
- O restore compara o hash do arquivo novamente lido com o snapshot já
  autenticado, fechando a janela de troca entre confirmação e instalação.
- Uma falha depois do `rename` é reportada como commit de durabilidade incerta,
  sem apagar uma recovery key que já possa corresponder ao cofre instalado.

## 9. Clipboard e i3

`pvault copy` cria o supervisor antes de descriptografar e seleciona o registro
no picker interno. O segredo nunca entra em `argv`, ambiente ou shell. Em X11 é
executado `/usr/bin/xclip`; em Wayland, `/usr/bin/wl-copy`. Um resultado de
transporte bem-sucedido significa que o payload foi escrito no pipe, o lado de
escrita foi fechado, o owner foi observado vivo e o timer foi armado; não prova
que o backend externo adquiriu uma seleção utilizável, por isso a CLI diz
"queued". Um `timerfd` baseado em `CLOCK_BOOTTIME` expira apenas o processo
owner criado pelo PVault após, por padrão, dez segundos; o tempo suspenso do
notebook também conta. Worker e owner normalizam a máscara e as disposições
herdadas de SIGTERM/SIGINT/SIGHUP/SIGCHLD. O owner configura
`PR_SET_PDEATHSIG`: se o supervisor sofrer crash, OOM ou `SIGKILL`, o kernel
envia `SIGTERM` ao owner em vez de deixá-lo oferecendo a senha indefinidamente.
Assim, um clipboard mais novo do usuário não é sobrescrito por uma limpeza
vazia.

No Wayland, texto UTF-8 sem NUL usa `text/plain;charset=utf-8`; slices binários
usam `application/octet-stream`, preservando bytes sem rotulá-los como texto.

Exemplo i3:

```text
bindsym $mod+p exec --no-startup-id alacritty -e pvault copy
```

## 10. Três arquiteturas possíveis para Android

### A. Mesmo arquivo + sincronização P2P

O Android reutiliza o formato e o núcleo C via NDK. Syncthing, ou ferramenta
P2P equivalente, transporta apenas o `.pvlt` entre dispositivos.

Vantagens: ausência de servidor central, implementação conceitualmente simples,
uso offline e mesmo formato auditável. Desvantagens: conflitos de arquivo
inteiro, risco de rollback e necessidade de preservar todas as cópias de
conflito. Antes de habilitar escrita nos dois lados será necessário um protocolo
de merge por `record.id/revision`, nunca “last writer wins” silencioso.

### B. Desktop como autoridade, Android por canal pareado

Um daemon local expõe operações mínimas por LAN/VPN, após pareamento presencial
por QR code e canal autenticado (Noise ou TLS mútuo). O Android pode manter cache
local cifrado ou operar sem cache.

Vantagens: não há conflito entre escritores e a política fica centralizada.
Desvantagens: o desktop precisa estar acessível, aumenta a superfície de rede e
exige revogação de dispositivos, rate limiting e proteção contra replay.

### C. Relay self-hosted de blobs opacos

Desktop e Android publicam snapshots criptografados e manifests assinados em um
servidor próprio, NAS ou VPS. O relay não recebe senha nem chave de conteúdo.

Vantagens: disponibilidade fora da LAN, histórico e múltiplos dispositivos sem
Big Tech. Desvantagens: maior complexidade operacional; ainda são necessários
detecção de forks/rollback, identidade por dispositivo, merge determinístico e
preservação de conflitos. Um WebDAV simples transporta bytes, mas sozinho não
resolve essas propriedades.

Para a primeira expansão, a opção A é a recomendada, inicialmente read-only no
Android. Ela maximiza reuso do núcleo e mantém a rede fora da base confiável. A
escrita móvel só deve ser liberada depois de existir merge testado e proteção
explícita contra rollback/forks.
