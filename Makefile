-include gomk/main.mk
-include local/Makefile

ifneq ($(unameS),Windows)
spellcheck:
	@codespell -f -L hilighter,keypair -S ".git,*.pem"
endif
