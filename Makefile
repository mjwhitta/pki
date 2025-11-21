-include gomk/main.mk
-include local/Makefile

ifneq ($(unameS),windows)
spellcheck:
	@codespell -f -L hilighter,keypair -S "*.pem,.git,go.*,gomk"
endif
