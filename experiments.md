## RQ1: system effectiveness

### E1 with Revelio: 10 arvo targets with verified --target-file

arvo-6521
python -m vulagent.run.detect \
  --arvo n132/arvo:6521-vul-clean \
  --pipeline scan_filter_detect \
  --target-file skcms/src/ICCProfile.c \
  --model claude-haiku-4-5-20251001 \
  --filter-model anthropic/claude-sonnet-4-6 \
  --poc-model anthropic/claude-sonnet-4-6 \
  --top-n 5 \
  --max-poc-attempts 5

arvo-14935
python -m vulagent.run.detect \
  --arvo n132/arvo:14935-vul-clean \
  --pipeline scan_filter_detect \
  --target-file libspng/spng.c \
  --model claude-haiku-4-5-20251001 \
  --filter-model anthropic/claude-sonnet-4-6 \
  --poc-model anthropic/claude-sonnet-4-6 \
  --top-n 5 \
  --max-poc-attempts 5

arvo-36861
python -m vulagent.run.detect \
  --arvo n132/arvo:36861-vul-clean \
  --pipeline scan_filter_detect \
  --target-file spice-usbredir/usbredirparser/usbredirparser.c \
  --model claude-haiku-4-5-20251001 \
  --filter-model anthropic/claude-sonnet-4-6 \
  --poc-model anthropic/claude-sonnet-4-6 \
  --top-n 5 \
  --max-poc-attempts 5

arvo-12818
MODEL_API_KEY="$ANTHROPIC_API_KEY_2" python -m vulagent.run.detect \
  --arvo n132/arvo:12818-vul-clean \
  --pipeline scan_filter_detect \
  --target-file kimageformats/src/imageformats/tga.cpp \
  --model claude-haiku-4-5-20251001 \
  --filter-model anthropic/claude-sonnet-4-6 \
  --poc-model anthropic/claude-sonnet-4-6 \
  --top-n 5 \
  --max-poc-attempts 5

arvo-14467
MODEL_API_KEY="$ANTHROPIC_API_KEY_3" python -m vulagent.run.detect \
  --arvo n132/arvo:14467-vul-clean \
  --pipeline scan_filter_detect \
  --target-file kimageformats/src/imageformats/tga.cpp \
  --model claude-haiku-4-5-20251001 \
  --filter-model anthropic/claude-sonnet-4-6 \
  --poc-model anthropic/claude-sonnet-4-6 \
  --top-n 5 \
  --max-poc-attempts 5

arvo-1065
MODEL_API_KEY="$ANTHROPIC_API_KEY_4" python -m vulagent.run.detect \
  --arvo n132/arvo:1065-vul-clean \
  --pipeline scan_filter_detect \
  --target-file file/src/funcs.c \
  --model claude-haiku-4-5-20251001 \
  --filter-model anthropic/claude-sonnet-4-6 \
  --poc-model anthropic/claude-sonnet-4-6 \
  --top-n 5 \
  --max-poc-attempts 5

arvo-24993
MODEL_API_KEY="$ANTHROPIC_API_KEY_2" python -m vulagent.run.detect \
  --arvo n132/arvo:24993-vul-clean \
  --pipeline scan_filter_detect \
  --target-file libheif/libheif/heif_colorconversion.cc \
  --model claude-haiku-4-5-20251001 \
  --filter-model anthropic/claude-sonnet-4-6 \
  --poc-model anthropic/claude-sonnet-4-6 \
  --top-n 5 \
  --max-poc-attempts 5

arvo-368
MODEL_API_KEY="$ANTHROPIC_API_KEY_3" python -m vulagent.run.detect \
  --arvo n132/arvo:368-vul-clean \
  --pipeline scan_filter_detect \
  --target-file freetype2/src/cff/cffload.c \
  --model claude-haiku-4-5-20251001 \
  --filter-model anthropic/claude-sonnet-4-6 \
  --poc-model anthropic/claude-sonnet-4-6 \
  --top-n 5 \
  --max-poc-attempts 5

arvo-10400
MODEL_API_KEY="$ANTHROPIC_API_KEY_4" python -m vulagent.run.detect \
  --arvo n132/arvo:10400-vul-clean \
  --pipeline scan_filter_detect \
  --target-file graphicsmagick/coders/png.c \
  --model claude-haiku-4-5-20251001 \
  --filter-model anthropic/claude-sonnet-4-6 \
  --poc-model anthropic/claude-sonnet-4-6 \
  --top-n 5 \
  --max-poc-attempts 5

arvo-47101
MODEL_API_KEY="$ANTHROPIC_API_KEY_2" python -m vulagent.run.detect \
  --arvo n132/arvo:47101-vul-clean \
  --pipeline scan_filter_detect \
  --target-file binutils-gdb/gas/dwarf2dbg.c \
  --model claude-haiku-4-5-20251001 \
  --filter-model anthropic/claude-sonnet-4-6 \
  --poc-model anthropic/claude-sonnet-4-6 \
  --top-n 5 \
  --max-poc-attempts 5

### E1 with Claude Code + Opus 4.7, Codex + GPT 5.5, KISS Sorcar + Opus 4.7
ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY_4" python experiment_analysis_scripts/claude_code_project_analysis.py \
  --arvo n132/arvo:6521-vul-clean \
  --target-file skcms/src/ICCProfile.c \
  --model claude-opus-4-7

bash experiment_launch_script/launch_claudecode_batch.sh
