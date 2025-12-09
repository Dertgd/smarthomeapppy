#BOT_TOKEN = "8275940796:AAH81zopQ_CETicjDbTqcoyErhjktUplnA0"
from telegram import Update, KeyboardButton, ReplyKeyboardMarkup, WebAppInfo
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

BOT_TOKEN = "8275940796:AAH81zopQ_CETicjDbTqcoyErhjktUplnA0"

async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    kb = ReplyKeyboardMarkup(
        [[KeyboardButton("Открыть SmartHome", web_app=WebAppInfo(url="https://YOUR_DOMAIN/webapp/"))]],
        resize_keyboard=True
    )
    await update.message.reply_text("Добро пожаловать!", reply_markup=kb)

app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.run_polling()
