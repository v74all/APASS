import os
import time
import psutil
from typing import List, Dict, Set, Optional
from datetime import datetime, timedelta
import asyncio

from telegram import Update
from telegram.ext import (
    CommandHandler, ContextTypes, ApplicationBuilder
)
from dotenv import load_dotenv

from utils import setup_logger, run_shell_command, async_run_shell_command, SecurityError, SecurityValidator

logger = setup_logger('bot_handlers', 'bot_handlers.log')

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")

authorized_ids_str = os.getenv("AUTHORIZED_USER_IDS", "")
AUTHORIZED_USER_IDS: List[int] = [
    int(id_str) for id_str in authorized_ids_str.split(",") if id_str.strip().isdigit()
] if authorized_ids_str else []

if not TELEGRAM_BOT_TOKEN:
    logger.error("Telegram bot token is not set. Please set it in the .env file.")
    exit(1)

if not AUTHORIZED_USER_IDS:
    logger.warning(
        "No authorized user IDs specified. The bot will be accessible to all users!"
    )

security_validator = SecurityValidator()

class UnauthorizedError(SecurityError):
    pass

rate_limits: Dict[int, float] = {}
RATE_LIMIT_SECONDS = 3

def rate_limit(func):
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        current_time = time.time()

        if user_id in rate_limits:
            time_passed = current_time - rate_limits[user_id]
            if time_passed < RATE_LIMIT_SECONDS:
                await update.message.reply_text(
                    f"Please wait {int(RATE_LIMIT_SECONDS - time_passed)} second(s) before using another command."
                )
                return

        rate_limits[user_id] = current_time
        return await func(update, context)
    return wrapper

async def authorize(update: Update, context: ContextTypes.DEFAULT_TYPE) -> bool:
    user_id = update.effective_user.id
    if AUTHORIZED_USER_IDS and user_id not in AUTHORIZED_USER_IDS:
        logger.warning(f"Unauthorized access attempt by user ID: {user_id}")
        await update.message.reply_text("You are not authorized to use this bot.")
        raise UnauthorizedError("User not authorized.")
    return True

BLOCKED_COMMANDS = ['rm', 'mkfs', 'dd', ':(){:|:&};:', 'wget', 'curl']
MAX_COMMAND_LENGTH = 500

class Session:
    def __init__(self, user_id: int):
        self.id = hash(f"{user_id}-{datetime.now()}")
        self.user_id = user_id
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.command_history = []
        self.failed_attempts = 0

class SessionManager:
    def __init__(self):
        self.sessions: Dict[int, Session] = {}
        self.max_sessions = 100
        self.session_timeout = 3600

    async def create_session(self, user_id: int) -> str:
        if len(self.sessions) >= self.max_sessions:
            await self.cleanup_sessions()

        if len(self.sessions) >= self.max_sessions:
            raise SecurityError("Maximum sessions reached")

        session = Session(user_id)
        self.sessions[user_id] = session
        return str(session.id)

    async def cleanup_sessions(self):
        current_time = datetime.now()
        expired = []
        for user_id, session in self.sessions.items():
            if (current_time - session.last_activity).total_seconds() > self.session_timeout:
                expired.append(user_id)
        for user_id in expired:
            del self.sessions[user_id]

    async def log_command(self, user_id: int, command: str):
        if user_id in self.sessions:
            session = self.sessions[user_id]
            session.command_history.append({
                'timestamp': datetime.now(),
                'command': command
            })
            session.last_activity = datetime.now()

            if len(session.command_history) > 1000:
                session.command_history = session.command_history[-1000:]

class RateLimiter:
    def __init__(self, limit: int = 5, window: int = 60):
        self.limit = limit
        self.window = window
        self._requests: Dict[int, List[datetime]] = {}

    async def check(self, user_id: int) -> bool:
        now = datetime.now()
        if user_id not in self._requests:
            self._requests[user_id] = []

        self._requests[user_id] = [
            req_time for req_time in self._requests[user_id]
            if now - req_time < timedelta(seconds=self.window)
        ]

        if len(self._requests[user_id]) >= self.limit:
            return False

        self._requests[user_id].append(now)
        return True

class PayloadSession:
    def __init__(self, payload_id: str, chat_id: int):
        self.payload_id = payload_id
        self.chat_id = chat_id
        self.connected = False
        self.last_seen = datetime.now()
        self.commands_history = []
        self.shell_buffer = ""

class PayloadController:
    def __init__(self):
        self.active_sessions: Dict[str, PayloadSession] = {}
        self.last_cleanup = datetime.now()
        self.command_queue = asyncio.Queue()
        self.message_queue = asyncio.Queue()
        
    async def handle_payload_connection(self, payload_id: str, chat_id: int):
        session = PayloadSession(payload_id, chat_id)
        self.active_sessions[payload_id] = session
        return f"New payload session established: {payload_id}"

    async def send_command(self, payload_id: str, command: str) -> bool:
        if payload_id not in self.active_sessions:
            return False
        session = self.active_sessions[payload_id]
        await self.command_queue.put((payload_id, command))
        session.commands_history.append(command)
        return True

    async def get_session_info(self, payload_id: str) -> Optional[dict]:
        if payload_id not in self.active_sessions:
            return None
        session = self.active_sessions[payload_id]
        return {
            "id": session.payload_id,
            "connected": session.connected,
            "last_seen": session.last_seen,
            "commands_count": len(session.commands_history)
        }

    async def enqueue_payload_message(self, payload_id: str, message: str):
        if payload_id not in self.active_sessions:
            return False
        session = self.active_sessions[payload_id]
        await self.message_queue.put((session.chat_id, f"[{payload_id}] {message}"))
        return True

    async def send_message_to_payload(self, payload_id: str, message: str) -> bool:
        if payload_id not in self.active_sessions:
            return False
        session = self.active_sessions[payload_id]
        session.shell_buffer += message + "\n"
        logger.info(f"Sending to payload {payload_id}: {message}")
        return True

class BotManager:
    def __init__(self):
        self.application = None
        self.logger = logger

        self.session_manager = SessionManager()

        self.security_validator = security_validator

        self.last_cleanup = time.time()

        self.rate_limiter = RateLimiter()

        self.command_batch: Dict[int, List[str]] = {}

        self.monitoring_tasks: Set[int] = set()

        self.payload_controller = PayloadController()

    async def validate_request(self, user_id: int) -> bool:
        return await self.rate_limiter.check(user_id)

    async def handle_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self.validate_request(update.effective_user.id):
            await update.message.reply_text("Too many requests. Please wait.")
            return

    async def execute_command(self, command: str) -> str:
        if not await self.security_validator.validate_command(command):
            raise SecurityError("Invalid or blocked command.")
        return await async_run_shell_command(command, self.logger)

    async def cleanup_sessions(self):
        current_time = time.time()
        if current_time - self.last_cleanup < 300:
            return

        await self.session_manager.cleanup_sessions()
        self.last_cleanup = current_time

    async def start_bot(self):
        self.application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

        setup_handlers(self.application, self)

        self.application.job_queue.run_repeating(
            monitoring_job, interval=60, first=10, data={'bot_manager': self}
        )

        self.logger.info("Starting bot...")
        await self.application.run_polling(drop_pending_updates=True)

    async def validate_command(self, command: str) -> bool:
        return await self.security_validator.validate_command(command)

    async def add_to_batch(self, user_id: int, command: str):
        if user_id not in self.command_batch:
            self.command_batch[user_id] = []
        self.command_batch[user_id].append(command)

    async def execute_batch(self, user_id: int) -> str:
        if user_id not in self.command_batch:
            return "No commands in batch to execute."

        results = []
        for cmd in self.command_batch[user_id]:
            try:
                result = await self.execute_command(cmd)
                results.append(f"Command: {cmd}\nResult:\n{result}")
            except SecurityError as e:
                results.append(f"Command: {cmd}\nError: {str(e)}")

        self.command_batch[user_id] = []
        return "\n\n".join(results)

    async def start_monitoring(self, user_id: int) -> str:
        if user_id in self.monitoring_tasks:
            return "Monitoring is already active for this user."
        self.monitoring_tasks.add(user_id)
        return "System monitoring started."

    async def stop_monitoring(self, user_id: int) -> str:
        if user_id not in self.monitoring_tasks:
            return "No active monitoring found for this user."
        self.monitoring_tasks.remove(user_id)
        return "System monitoring stopped."

    async def process_message_queue(self, context: ContextTypes.DEFAULT_TYPE):
        while not self.payload_controller.message_queue.empty():
            chat_id, message = await self.payload_controller.message_queue.get()
            try:
                await context.bot.send_message(chat_id=chat_id, text=message)
            except Exception as e:
                logger.error(f"Failed to send message to chat {chat_id}: {e}")
            self.payload_controller.message_queue.task_done()

    async def get_system_metrics(self) -> dict:
        return {
            'cpu': psutil.cpu_percent(interval=1),
            'memory': psutil.virtual_memory().percent,
            'disk': psutil.disk_usage('/').percent,
            'network': len(psutil.net_connections())
        }

    async def stop_bot(self) -> bool:
        if self.application:
            await self.application.shutdown()
            await self.application.stop()
            await self.application.update_persistence()
            self.application = None
            logger.info("Bot stopped successfully.")
            return True
        logger.warning("Bot is not running.")
        return False

    async def get_bot_status(self) -> dict:
        if self.application and bot_state.start_time:
            uptime = time.time() - bot_state.start_time
            return {
                'running': True,
                'uptime': uptime,
                'active_sessions': len(self.session_manager.sessions),
                'messages_processed': bot_state.messages_processed
            }
        return {'running': False}

async def monitoring_job(context: ContextTypes.DEFAULT_TYPE):
    job_data = context.job.data or {}
    bot_manager: BotManager = job_data.get('bot_manager')
    if not bot_manager:
        return

    metrics = await bot_manager.get_system_metrics()
    message = (
        f"**System Monitoring**\n\n"
        f"CPU: {metrics['cpu']}%\n"
        f"Memory: {metrics['memory']}%\n"
        f"Disk: {metrics['disk']}%\n"
        f"Network Connections: {metrics['network']}"
    )

    for user_id in bot_manager.monitoring_tasks:
        try:
            await context.bot.send_message(chat_id=user_id, text=message, parse_mode="MarkdownV2")
        except Exception as e:
            logger.exception(f"Failed to send monitoring message to user {user_id}: {e}")

@rate_limit
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_manager: BotManager):
    try:
        await authorize(update, context)
        session_id = await bot_manager.session_manager.create_session(update.effective_user.id)
        await update.message.reply_text(
            f"Bot started. Session ID: {session_id}\nUse /help to see available commands."
        )
        logger.info(f"Bot started by user ID: {update.effective_user.id}")
    except UnauthorizedError:
        pass
    except SecurityError as e:
        await update.message.reply_text(f"Security Error: {str(e)}")

@rate_limit
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_manager: BotManager):
    try:
        await authorize(update, context)
        help_text = (
            "Available Commands:\n\n"
            "/start - Start the bot and create a new session.\n"
            "/help - Show available commands.\n"
            "/shell <command> - Execute a shell command (with restrictions).\n"
            "/status - Get basic system status (uptime, disk, memory).\n"
            "/processes - Show top 20 processes by CPU/memory usage.\n"
            "/batch <command> - Add a command to the batch queue.\n"
            "  (Use /batch with no arguments to run all batched commands.)\n"
            "/monitor start - Start periodic system monitoring.\n"
            "/monitor stop - Stop system monitoring.\n"
            "/payload - Control payloads (list, connect, shell, kill).\n"
            "/user_message <payload_id> <message> - Send a message to a payload.\n"
        )
        await update.message.reply_text(help_text)
    except UnauthorizedError:
        pass

@rate_limit
async def shell_command(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_manager: BotManager):
    try:
        await authorize(update, context)
        if not context.args:
            await update.message.reply_text("Please provide a command to execute, e.g., /shell ls -la")
            return

        command = ' '.join(context.args)
        if not await bot_manager.validate_command(command):
            await update.message.reply_text("This command is not allowed or is invalid.")
            return

        output = await async_run_shell_command(command, logger)
        await update.message.reply_text(f"Output:\n{output}")
    except Exception as e:
        logger.exception(f"Shell command error: {e}")
        await update.message.reply_text(f"Error: {str(e)}")

@rate_limit
async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_manager: BotManager):
    try:
        await authorize(update, context)
        uptime = await run_shell_command("uptime", logger)
        disk_usage = await run_shell_command("df -h", logger)
        memory_usage = await run_shell_command("free -m", logger)

        status_message = (
            f"**Uptime:**\n```\n{uptime}\n```\n"
            f"**Disk Usage:**\n```\n{disk_usage}\n```\n"
            f"**Memory Usage:**\n```\n{memory_usage}\n```"
        )
        await update.message.reply_text(status_message, parse_mode="MarkdownV2")
    except UnauthorizedError:
        pass
    except Exception as e:
        logger.exception(f"Error in status_command: {e}")
        await update.message.reply_text(f"Error getting system status: {e}")

@rate_limit
async def processes_command(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_manager: BotManager):
    try:
        await authorize(update, context)

        process_list = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                process_list.append(
                    f"PID: {info['pid']}, Name: {info['name']}, "
                    f"CPU: {info['cpu_percent']}%, RAM: {info['memory_percent']:.1f}%"
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        response = "\n".join(process_list[:20]) if process_list else "No process information available."
        await update.message.reply_text(f"Top 20 Processes:\n\n{response}")
    except Exception as e:
        logger.exception(f"Error in processes_command: {e}")
        await update.message.reply_text(f"Error getting process list: {e}")

@rate_limit
async def batch_command(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_manager: BotManager):
    try:
        await authorize(update, context)
        if not context.args:
            results = await bot_manager.execute_batch(update.effective_user.id)
            await update.message.reply_text(results)
            return

        command = ' '.join(context.args)
        await bot_manager.add_to_batch(update.effective_user.id, command)
        await update.message.reply_text("Command added to batch. Use /batch with no arguments to execute all.")
    except Exception as e:
        logger.exception(f"Batch command error: {e}")
        await update.message.reply_text(f"Error: {str(e)}")

@rate_limit
async def monitor_command(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_manager: BotManager):
    try:
        await authorize(update, context)
        if not context.args:
            await update.message.reply_text("Usage: /monitor [start|stop]")
            return

        action = context.args[0].lower()
        if action == "start":
            result = await bot_manager.start_monitoring(update.effective_user.id)
        elif action == "stop":
            result = await bot_manager.stop_monitoring(update.effective_user.id)
        else:
            result = "Invalid argument. Use /monitor [start|stop]"

        await update.message.reply_text(result)
    except Exception as e:
        logger.exception(f"Monitor command error: {e}")
        await update.message.reply_text(f"Error: {str(e)}")

@rate_limit
async def payload_command(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_manager: BotManager):
    try:
        await authorize(update, context)
        if not context.args:
            await update.message.reply_text(
                "Usage:\n"
                "/payload list - List active payloads\n"
                "/payload connect <id> - Connect to payload\n"
                "/payload shell <id> <cmd> - Send command\n" 
                "/payload kill <id> - Terminate payload"
            )
            return

        action = context.args[0].lower()
        controller = bot_manager.payload_controller

        if action == "list":
            sessions = []
            for payload_id, session in controller.active_sessions.items():
                info = await controller.get_session_info(payload_id)
                if info:
                    sessions.append(
                        f"ID: {info['id']}\n"
                        f"Status: {'🟢 Connected' if info['connected'] else '🔴 Disconnected'}\n"
                        f"Last seen: {info['last_seen']}\n"
                        f"Commands: {info['commands_count']}\n"
                    )
            if sessions:
                await update.message.reply_text("Active payloads:\n\n" + "\n".join(sessions))
            else:
                await update.message.reply_text("No active payloads")

        elif action == "connect" and len(context.args) > 1:
            payload_id = context.args[1]
            result = await controller.handle_payload_connection(
                payload_id, 
                update.effective_chat.id
            )
            await update.message.reply_text(result)

        elif action == "shell" and len(context.args) > 2:
            payload_id = context.args[1]
            command = " ".join(context.args[2:])
            if await controller.send_command(payload_id, command):
                await update.message.reply_text(f"Command sent to payload {payload_id}")
            else:
                await update.message.reply_text(f"Payload {payload_id} not found or not connected")

        elif action == "kill" and len(context.args) > 1:
            payload_id = context.args[1]
            if payload_id in controller.active_sessions:
                del controller.active_sessions[payload_id]
                await update.message.reply_text(f"Payload {payload_id} terminated")
            else:
                await update.message.reply_text(f"Payload {payload_id} not found")

    except UnauthorizedError:
        pass
    except Exception as e:
        logger.error(f"Payload command error: {e}")
        await update.message.reply_text(f"Error: {str(e)}")

@rate_limit
async def payload_message(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_manager: BotManager):
    try:
        payload_id = context.args[0]
        message = ' '.join(context.args[1:])

        if await bot_manager.payload_controller.enqueue_payload_message(payload_id, message):
            logger.info(f"Message from payload {payload_id} enqueued.")
        else:
            await update.message.reply_text(f"Payload {payload_id} not found.")
    except Exception as e:
        logger.error(f"Error processing payload message: {e}")
        await update.message.reply_text(f"Error processing payload message: {str(e)}")

@rate_limit
async def user_message(update: Update, context: ContextTypes.DEFAULT_TYPE, bot_manager: BotManager):
    try:
        await authorize(update, context)
        if not context.args or len(context.args) < 2:
            await update.message.reply_text("Usage: /user_message <payload_id> <message>")
            return

        payload_id = context.args[0]
        message = ' '.join(context.args[1:])

        if await bot_manager.payload_controller.send_message_to_payload(payload_id, message):
            await update.message.reply_text(f"Message sent to payload {payload_id}.")
        else:
            await update.message.reply_text(f"Payload {payload_id} not found.")

    except UnauthorizedError:
        pass
    except Exception as e:
        logger.error(f"Error sending message to payload: {e}")
        await update.message.reply_text(f"Error: {str(e)}")

def setup_handlers(application, bot_manager: BotManager):
    application.add_handler(CommandHandler("start", lambda u, c: start(u, c, bot_manager)))
    application.add_handler(CommandHandler("help", lambda u, c: help_command(u, c, bot_manager)))
    application.add_handler(CommandHandler("shell", lambda u, c: shell_command(u, c, bot_manager)))
    application.add_handler(CommandHandler("status", lambda u, c: status_command(u, c, bot_manager)))
    application.add_handler(CommandHandler("processes", lambda u, c: processes_command(u, c, bot_manager)))
    application.add_handler(CommandHandler("batch", lambda u, c: batch_command(u, c, bot_manager)))
    application.add_handler(CommandHandler("monitor", lambda u, c: monitor_command(u, c, bot_manager)))
    application.add_handler(CommandHandler("payload", lambda u, c: payload_command(u, c, bot_manager)))
    application.add_handler(CommandHandler("user_message", lambda u, c: user_message(u, c, bot_manager)))

    application.add_handler(CommandHandler("payload_message", lambda u, c: payload_message(u, c, bot_manager)))

    logger.info("Bot handlers have been registered.")

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any
import json
import sys
from pathlib import Path

logger = logging.getLogger('bot_handlers')

class BotState:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.running = False
            cls._instance.start_time = None
            cls._instance.active_sessions = 0
            cls._instance.messages_processed = 0
            cls._instance.tasks = set()
        return cls._instance

    def reset(self):
        self.running = False
        self.start_time = None
        self.active_sessions = 0
        self.messages_processed = 0
        self.tasks = set()

bot_state = BotState()

async def process_shell_command(command: str) -> str:
    try:
        if not bot_state.running:
            return "Bot is not running. Start the bot first."

        if command.strip().lower() in ['exit', 'quit']:
            return "Use 'apass bot stop' to stop the bot."

        bot_state.messages_processed += 1

        response = f"Processed command: {command}"
        logger.info(f"Processed shell command: {command}")
        
        return response

    except Exception as e:
        logger.error(f"Error processing shell command: {str(e)}")
        return f"Error: {str(e)}"

async def monitor_bot_activity(duration: int = 60) -> Dict[str, Any]:
    try:
        start_messages = bot_state.messages_processed
        start_sessions = bot_state.active_sessions
        start_time = datetime.now()
        
        await asyncio.sleep(duration)
        
        return {
            'duration': duration,
            'commands_processed': bot_state.messages_processed - start_messages,
            'messages_received': bot_state.messages_processed - start_messages,
            'active_users': bot_state.active_sessions,
            'errors': 0,
            'start_time': start_time.isoformat(),
            'end_time': datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"Error monitoring bot activity: {str(e)}")
        return {
            'error': str(e)
        }

async def monitor_bot_internals():
    try:
        while True:
            if not bot_state.running:
                break

            memory_usage = sys.getsizeof(bot_state) / 1024 / 1024
            uptime = datetime.now() - bot_state.start_time

            logger.debug(f"Bot Metrics - Memory: {memory_usage:.2f}MB, "
                        f"Uptime: {uptime}, "
                        f"Messages: {bot_state.messages_processed}")

            await asyncio.sleep(60)

    except asyncio.CancelledError:
        logger.info("Bot monitoring task cancelled")
    except Exception as e:
        logger.error(f"Error in bot monitoring: {str(e)}")

def save_bot_state():
    try:
        state = {
            'running': bot_state.running,
            'start_time': bot_state.start_time.isoformat() if bot_state.start_time else None,
            'active_sessions': bot_state.active_sessions,
            'messages_processed': bot_state.messages_processed
        }
        
        state_file = Path('bot_state.json')
        with state_file.open('w') as f:
            json.dump(state, f)
            
    except Exception as e:
        logger.error(f"Error saving bot state: {str(e)}")

def load_bot_state():
    try:
        state_file = Path('bot_state.json')
        if not state_file.exists():
            return
            
        with state_file.open('r') as f:
            state = json.load(f)
            
        if state.get('running'):
            bot_state.running = True
            bot_state.start_time = datetime.fromisoformat(state['start_time']) if state['start_time'] else None
            bot_state.active_sessions = state['active_sessions']
            bot_state.messages_processed = state['messages_processed']
            
    except Exception as e:
        logger.error(f"Error loading bot state: {str(e)}")

async def start_bot():
    try:
        if bot_state.running:
            logger.warning("Bot is already running")
            return True

        bot_manager = BotManager()
        bot_state.running = True
        bot_state.start_time = time.time()
        
        logger.info("Starting bot...")
        await bot_manager.start_bot()
        
        monitoring_task = asyncio.create_task(monitor_bot_internals())
        bot_state.tasks.add(monitoring_task)
        
        return True

    except Exception as e:
        logger.error(f"Failed to start bot: {e}")
        bot_state.reset()
        raise

async def stop_bot():
    try:
        if not bot_state.running:
            logger.warning("Bot is not running")
            return True

        bot_manager = BotManager()
        result = await bot_manager.stop_bot()
        
        for task in bot_state.tasks:
            task.cancel()
        bot_state.tasks.clear()
        
        save_bot_state()
        bot_state.reset()
        
        logger.info("Bot stopped successfully")
        return result

    except Exception as e:
        logger.error(f"Failed to stop bot: {e}")
        raise

async def get_bot_status():
    try:
        bot_manager = BotManager()
        return await bot_manager.get_bot_status()
    except Exception as e:
        logger.error(f"Failed to get bot status: {e}")
        raise
