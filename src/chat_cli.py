"""Talk to the target chatbot by hand. Type /reset to clear history, /quit to exit."""
from target import Target, leaked, overridden

bot = Target()
print("HelpBot (Fjord Books). /reset to clear, /quit to exit.\n")
while True:
    try:
        msg = input("you> ").strip()
    except (EOFError, KeyboardInterrupt):
        break
    if msg == "/quit":
        break
    if msg == "/reset":
        bot = Target()
        print("[history cleared]\n")
        continue
    if not msg:
        continue
    out = bot.reply(msg)
    print(f"bot> {out}")
    flags = [n for n, hit in (("LEAKED", leaked(out)), ("OVERRIDDEN", overridden(out))) if hit]
    if flags:
        print(f"  [!] {', '.join(flags)}")
    print()
