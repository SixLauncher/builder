# vilauncher-builder

Compila, para o VILauncher, os projetos que o [PortWatch VI](https://github.com/4lwayz/portwatch-vi)
avalia com **59% ou mais**. Roda no Railway como cron, **a cada 3 horas**.

A cada execução (`builder/build.py`):

1. lê o `tracker.json` do PortWatch VI e calcula a nota de cada projeto como o site (0–100);
2. fica com os que têm código público e nota ≥ `MIN_SCORE` (59), do melhor para o pior;
3. descobre o tipo de cada repositório pelo branch padrão: árvore do VIctory
   (`apps/victory/Cargo.toml`) ou do XCL (`crates/xcl/Cargo.toml`); o resto é pulado, com o motivo;
4. compila o commit mais novo para Windows a partir do Linux com
   [cargo-xwin](https://github.com/rust-cross/cargo-xwin) (`x86_64-pc-windows-msvc`), com o
   toolchain que o próprio repositório fixa. Um repositório e commit já publicados não são recompilados;
5. passa o resultado no VirusTotal (`builder/virustotal-scan.py`). Se o programa principal
   (`victory.exe`, ou `xcl.exe` e as DLLs dele) for marcado, a build não é publicada; um programa
   extra marcado (como o `victory-play.exe` do DexNom) sai do pacote, fica registrado em `dropped` no
   `runtimes.json`, e o resto é publicado;
6. publica cada build como `.tar.gz` na release `runtimes` deste repositório, depois o
   `runtimes.json`, e apaga os arquivos que o manifesto novo não cita mais.

Repositórios acompanhados pelo nome (`EXTRA` em `builder/build.py`): hoje o
[VIctory-macOS](https://github.com/romainhedouin/VIctory-macOS) e o
[VIctory-Belobug-AMD](https://github.com/romainhedouin/VIctory-Belobug-AMD) do romainhedouin. Eles
passam pela mesma conferência dupla dos outros: só são compilados quando o PortWatch VI os lista com
nota ≥ `MIN_SCORE`; até lá o log diz que estão aguardando. A lista só acrescenta o que o tracker não
diz: uma build com `platform: "macos"` só aparece no VILauncher para macOS (e nunca é a padrão da
família).

O `runtimes.json` mantém o formato que o VILauncher já lê: `victory` e `xcl` são a melhor build de
cada família (launchers antigos continuam funcionando) e `builds` lista todas, com a nota, para o
launcher deixar escolher. Alguns forks deixam fora do repositório dados que o próprio setup deles baixa (o DexNom, as tabelas
BCPack em `crates/victory-formats/src/bcpack-tables.bin`): quando a pasta existe e o arquivo falta, o
builder baixa a cópia do commit fixo do Marvisak/VIctory e confere o SHA-256 antes de compilar
(`SUPPLIED` em `builder/build.py`). O pacote leva todos os programas que o projeto gera (no DexNom,
também `victory-play.exe` e `victory-warm.exe`). O xcl vai com `dxcompiler.dll`/`dxil.dll` (última release do DXC) e
`opus.dll` (pacote UCRT64 do MSYS2, fixado por versão e SHA-256 no `Dockerfile`).

## Segurança

O código dos projetos é de terceiros. Por isso ele é compilado pelo usuário sem privilégios `build`,
com o ambiente limpo (nenhum segredo do serviço chega aos `build.rs`), e todo processo dele é
encerrado ao fim de cada build. O que é verificado, empacotado e enviado fica numa pasta só do root.

## Implantar no Railway

1. **New Project → Deploy from GitHub repo** → este repositório. O Railway lê o `railway.json`:
   build pelo `Dockerfile`, cron `0 */3 * * *` (UTC) e sem reinício automático.
2. Em **Variables**:
   - `GITHUB_TOKEN`: token *fine-grained* só deste repositório, com **Contents: Read and write**
     (cria a release e envia os arquivos);
   - `VT_API_KEY` (opcional): chave do VirusTotal; sem ela as builds saem com verdict `skipped`;
   - opcionais: `MIN_SCORE` (59), `MAX_NEW_BUILDS` (4 por execução), `BUILD_TIMEOUT` (3600 s).
3. A primeira imagem demora (Rust, cargo-xwin e o SDK do Windows ficam dentro dela). Ao baixar o
   CRT e o SDK, o cargo-xwin aceita a licença da Microsoft para eles.

Para testar sem publicar: `DRY_RUN=1` (imprime o `runtimes.json`).

O VILauncher baixa de
`https://github.com/SixLauncher/vilauncher-builder/releases/download/runtimes/runtimes.json`
(trocável com `VILAUNCHER_RUNTIMES_URL`).

## Testes

```
python3 -I -m unittest discover -s builder
```
