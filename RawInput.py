
import os
import io
import sys
import threading
import time

IS_WIN32 = os.name == 'nt'

if IS_WIN32:
	import msvcrt
else:
	import tty
	import termios

import mcdreforged.api.all as MCDR

PLUGIN_METADATA = {
  'id': 'rawinput',
  'version': '1.0.2',
  'name': 'RawInput',
  'description': 'Minecraft better console!',
  'author': 'zyxgad',
  'link': 'https://github.com/zyxgad/rawinput_mcdr',
  'dependencies': {
    'mcdreforged': '>=1.0.0'
  }
}

default_config = {
	'prefix': '>'
}
config = default_config.copy()

MSG_ID = MCDR.RText('[RI]', color=MCDR.RColor.dark_red)

SERVER_OBJ = None
read_write = None

def send_message(source: MCDR.CommandSource, *args, sep=' ', prefix=MSG_ID):
  if source is not None:
    source.reply(MCDR.RTextList(prefix, args[0], *([MCDR.RTextList(sep, a) for a in args][1:])))

def broadcast_message(*args, sep=' ', prefix=MSG_ID):
  if SERVER_OBJ is not None:
    SERVER_OBJ.broadcast(MCDR.RTextList(prefix, args[0], *([MCDR.RTextList(sep, a) for a in args][1:])))

def log_info(*args, sep=' ', prefix=MSG_ID):
  if SERVER_OBJ is not None:
    SERVER_OBJ.logger.info(MCDR.RTextList(prefix, args[0], *([MCDR.RTextList(sep, a) for a in args][1:])))


#####################################
BREAK_ID = 0x03
TAB_ID = 0x09
NEW_LINE_ID = 0x0d
ESC_ID = 0x1b
MOVE_ID = 0x5b
MOVE_UP_ID = 0x41
MOVE_DOWN_ID = 0x42
MOVE_RIGHT_ID = 0x43
MOVE_LEFT_ID = 0x44
BACKSPACE_ID = 0x7f

MOVE_RIGHT_CHAR = '\x1b\x5b\x43'
MOVE_LEFT_CHAR = '\x1b\x5b\x44'
#####################################

class RawReader(io.RawIOBase):
	def __init__(self, reader, writer, prefix='', *, mixin=False):
		self.__isinterrupt = False
		self.__isclose = False
		self.__helper_thr = None
		self._prefix = prefix
		self._mixin_map = {}
		self._mixin = mixin
		self.__old_settings = None
		self.__pid = os.getpid()
		self._buffer_lock = threading.RLock()
		self._empty_lock = threading.Condition(self._buffer_lock)
		self._write_lock = threading.RLock()
		self._buffer = io.BytesIO()
		self._histories = []
		self.__line_his_buf = ''
		self.__current_his = 0
		self.__line_buf = []
		self.__line_index = 0
		assert reader.readable() and reader.isatty(), "输入流必须是(伪)终端设备"
		self._reader = reader
		self._reader_fd = self._reader.fileno()
		assert writer.writable()
		self._writer = writer
		if not IS_WIN32:
			self.__old_settings = termios.tcgetattr(self._reader_fd)
			try:
				mode = termios.tcgetattr(self._reader_fd)
				mode[tty.IFLAG] &= ~(termios.BRKINT | termios.INPCK | termios.IXON)
				mode[tty.IFLAG] |= termios.ICRNL
				mode[tty.CFLAG] &= ~(termios.CSIZE | termios.PARENB)
				mode[tty.CFLAG] |= termios.CS8
				mode[tty.LFLAG] &= ~(termios.ICANON | termios.ECHO | termios.ISIG)
				mode[tty.CC][termios.VMIN] = 1
				mode[tty.CC][termios.VTIME] = 0
				termios.tcsetattr(self._reader_fd, termios.TCSADRAIN, mode)
			except:
				self.close()
				raise
		if self._mixin:
			self.__mix(self._reader, 'read')
			self.__mix(self._reader, 'readline')
			self.__mix(self._reader, 'readlines')
			self.__mix(self._writer, 'write')
			self.__mix(self._writer, 'writelines')
		self.__helper_thr = threading.Thread(target=self.__helper, name='raw-reader(r:{},w:{})'.
			format(self._reader.fileno(), self._writer.fileno()))
		self.__helper_thr.setDaemon(True)
		self.__helper_thr.start()

	@property
	def prefix(self):
		return self._prefix

	@prefix.setter
	def prefix(self, prefix):
		self._prefix = prefix

	@property
	def reader(self):
		return self._reader

	@property
	def writer(self):
		return self._writer

	def __mix(self, obj, key):
		if self._mixin:
			new = getattr(self, key)
			if hasattr(obj, key):
				old = getattr(obj, key)
				i = id(obj)
				if i not in self._mixin_map:
					self._mixin_map[i] = [obj, {}]
				self._mixin_map[i][1][key] = old
			setattr(obj, key, new)

	def _get_mixin_attr(self, obj, key):
		if self._mixin:
			return self._mixin_map.get(id(obj), [None, {}])[1].get(key, getattr(obj, key))
		return getattr(obj, key)

	def unload_mixin(self):
		for _, mmap in self._mixin_map.items():
			obj = mmap[0]
			for key, old in mmap[1].items():
				setattr(obj, key, old)

	def _check_end_or_interrupt(self):
		if self.__isinterrupt:
			raise KeyboardInterrupt()
		if self.__isclose:
			raise EOFError()

	def flush(self):
		self._writer.flush()

	def readable(self):
		return True

	def writable(self):
		return True

	def seekable(self):
		return False

	def fileno(self):
		return self._reader.fileno()

	def _flush_empty_buf(self):
		self._check_end_or_interrupt()
		if self._buffer.tell() == len(self._buffer.getvalue()):
			self._buffer = io.BytesIO()

	def _wait_empty(self):
		if self._buffer.tell() == len(self._buffer.getvalue()):
			with self._empty_lock:
				self._empty_lock.wait()
				self._check_end_or_interrupt()

	def read(self, size=-1):
		self._check_end_or_interrupt()
		with self._buffer_lock:
			self._flush_empty_buf()
			self._wait_empty()
			return self._buffer.read(size).decode('utf-8')

	def readline(self, size=-1):
		self._check_end_or_interrupt()
		with self._buffer_lock:
			self._flush_empty_buf()
			self._wait_empty()
			return self._buffer.readline(size).decode('utf-8')

	def readlines(self, hint=-1):
		self._check_end_or_interrupt()
		with self._buffer_lock:
			self._flush_empty_buf()
			self._wait_empty()
			return [l.decode('utf-8') for l in self._buffer.readlines(hint)]

	def write(self, data):
		self._check_end_or_interrupt()
		with self._write_lock:
			self._check_end_or_interrupt()
			line = ''.join(self.__line_buf)
			lline = len(self._prefix) + len(line)
			self.__write(MOVE_LEFT_CHAR * (len(self._prefix) + self.__line_index))
			self.__write(' ' * lline)
			self.__write(MOVE_LEFT_CHAR * lline)
			self.__write(data)
			self.__write(self._prefix); self.__write(line)
			self.__write(MOVE_LEFT_CHAR * (len(line) - self.__line_index))
			self._writer.flush()

	def writelines(self, lines):
		self._check_end_or_interrupt()
		with self._write_lock:
			self._check_end_or_interrupt()
			line = ''.join(self.__line_buf)
			lline = len(line)
			self.__write(MOVE_LEFT_CHAR * self.__line_index)
			self.__write(' ' * lline)
			self.__write(MOVE_LEFT_CHAR * lline)
			for data in lines:
				self.__write(data)
			self.__write(self._prefix); self.__write(line)
			self.__write(MOVE_LEFT_CHAR * (lline - self.__line_index))
			self._writer.flush()

	if IS_WIN32:
		def __readchar(self):
			return msvcrt.getch()
	else:
		def __readchar(self):
			return self.__read(1)

	def __read(self, size=-1):
		return (self._get_mixin_attr(self._reader, 'read') if self._mixin else self._reader.read)(size)

	def __readline(self, size=-1):
		return (self._get_mixin_attr(self._reader, 'readline') if self._mixin else self._reader.readline)(size)

	def __readlines(self, hint=-1):
		return (self._get_mixin_attr(self._reader, 'readlines') if self._mixin else self._reader.readlines)(size)

	def __write(self, data):
		return (self._get_mixin_attr(self._writer, 'write') if self._mixin else self._writer.write)(data)

	def __helper_on_move_focus(self):
		ch = self.__readchar()
		chid = ord(ch)
		if chid == MOVE_LEFT_ID:
			if self.__line_index > 0:
				self.__line_index -= 1
				self.__write(MOVE_LEFT_CHAR)
		elif chid == MOVE_RIGHT_ID:
			if self.__line_index < len(self.__line_buf):
				self.__line_index += 1
				self.__write(MOVE_RIGHT_CHAR)
		elif chid == MOVE_UP_ID:
			self.__helper_last_history()
		elif chid == MOVE_DOWN_ID:
			self.__helper_next_history()

	def __helper_change_line(self, new_line):
		lline = len(self.__line_buf)
		self.__write(MOVE_LEFT_CHAR * self.__line_index)
		self.__write(' ' * lline)
		self.__write(MOVE_LEFT_CHAR * lline)
		self.__write(new_line)

	def __helper_last_history(self):
		if self.__current_his >= len(self._histories):
			return
		if self.__current_his == 0:
			self.__line_his_buf = ''.join(self.__line_buf)
		self.__current_his += 1
		hist = self._histories[-self.__current_his]
		self.__helper_change_line(hist)
		self.__line_buf = list(hist)
		self.__line_index = len(hist)

	def __helper_next_history(self):
		if self.__current_his <= 0:
			return
		self.__current_his -= 1
		hist = self._histories[-self.__current_his] if self.__current_his > 0 else self.__line_his_buf
		self.__helper_change_line(hist)
		self.__line_buf = list(hist)
		self.__line_index = len(hist)

	def __helper_on_enter(self):
		self.__write(os.linesep)
		self.__write(self._prefix)
		if len(self.__line_buf) > 0:
			line = ''.join(self.__line_buf)
			self.__line_buf.clear()
			self.__line_index = 0
			if len(self._histories) == 0 or self._histories[-1] != line:
				self._histories.append(line)
			self.__current_his = 0
			with self._empty_lock:
				index = self._buffer.tell()
				self._buffer.seek(0, os.SEEK_END)
				self._buffer.write(line.encode('utf-8'))
				self._buffer.write(os.linesep.encode('utf-8'))
				self._buffer.seek(index, os.SEEK_SET)
				self._empty_lock.notify()

	def __helper_delete_char(self):
		if self.__line_index == 0:
			return
		self.__line_index -= 1
		self.__line_buf.pop(self.__line_index)
		if self.__line_index < len(self.__line_buf):
			tail = ''.join(self.__line_buf[self.__line_index:])
			ltail = len(tail)
			self.__write(MOVE_LEFT_CHAR)
			self.__write(tail)
			self.__write(' ')
			self.__write(MOVE_LEFT_CHAR * (ltail + 1))
		else:
			self.__write(MOVE_LEFT_CHAR)
			self.__write(' ')
			self.__write(MOVE_LEFT_CHAR)

	def __helper_insert_char(self, ch):
		self.__line_buf.insert(self.__line_index, ch)
		self.__line_index += 1
		self.__write(ch)
		if self.__line_index < len(self.__line_buf):
			tail = ''.join(self.__line_buf[self.__line_index:])
			self.__write(tail)
			self.__write(MOVE_LEFT_CHAR * len(tail))

	def __helper(self):
		self.__line_buf.clear()
		self.__line_index = 0
		try:
			with self._write_lock:
				self.__write(self._prefix)
				self._writer.flush()
			while not self.__isclose:
				ch = self.__readchar()
				if self.__isclose:
					break
				chid = ord(ch)
				if chid == BREAK_ID:
					self.__isinterrupt = True
					break
				if isinstance(ch, bytes): ch = try_decodes(ch, ['utf-8', 'gbk'])
				with self._write_lock:
					if chid == ESC_ID:
						ch2 = self.__readchar()
						chid2 = ord(ch2)
						if chid2 == MOVE_ID:
							self.__helper_on_move_focus()
					elif chid == BACKSPACE_ID:
						self.__helper_delete_char()
					elif chid == TAB_ID:
						pass
					elif ch == '\r' or ch == '\n':
						self.__helper_on_enter()
					elif ch.isprintable():
						self.__helper_insert_char(ch)
					self._writer.flush()
		except OSError:
			pass
		finally:
			self.close()

	def __enter__(self):
		return self

	def __exit__(self, err_cls, err_msg, traceback):
		self.close()
		if err_cls is not None and not isinstance(err_cls, EOFError):
			return False
		return True

	def close_rw(self):
		self._reader.close()
		self._writer.close()

	@property
	def closed(self):
		return self.__isclose

	def close(self):
		if self.__pid != os.getpid():
			return
		if self.__isclose:
			return
		self.__isclose = True
		self.unload_mixin()
		if self.__old_settings is not None:
			termios.tcsetattr(self._reader_fd, termios.TCSADRAIN, self.__old_settings)
			self.__old_settings = None
		with self._empty_lock:
			self._empty_lock.notify_all()
		if self.__helper_thr is not None:
			self.__helper_thr = None

	def __del__(self):
		if self.__pid == os.getpid():
			self.close()

def try_decodes(string, encodes):
	for e in encodes:
		try:
			return string.decode(e)
		except UnicodeDecodeError:
			pass
	raise UnicodeDecodeError('Failed to decode {}, with encodes {}'.format(repr(string), str(encodes)))

######### Mixins #########

def _mixin_ConsoleHandler_tick():
	from mcdreforged.executor.console_handler import ConsoleHandler
	from mcdreforged.info import Info
	from mcdreforged.utils.logger import DebugOption, SyncStreamHandler
	def tick(self):
		try:
			text = input()
			parsed_result: Info
			try:
				parsed_result = self.mcdr_server.server_handler_manager.get_current_handler().parse_console_command(text)
			except:
				self.mcdr_server.logger.exception(self.mcdr_server.tr('console_handler.parse_fail', text))
			else:
				if self.mcdr_server.logger.should_log_debug(DebugOption.HANDLER):
					self.mcdr_server.logger.debug('Parsed text from {}:'.format(type(self).__name__), no_check=True)
					for line in parsed_result.format_text().splitlines():
						self.mcdr_server.logger.debug('    {}'.format(line), no_check=True)
				self.mcdr_server.reactor_manager.put_info(parsed_result)
		except KeyboardInterrupt:
			if self.mcdr_server.is_server_running() and not self.mcdr_server.is_interrupt():
				self.mcdr_server.interrupt()
		except (EOFError, SystemExit, IOError) as error:
			if self.mcdr_server.is_server_running():
				self.mcdr_server.logger.critical('Critical exception caught in {}: {} {}'.format(type(self).__name__, type(error).__name__, error))
				self.mcdr_server.interrupt()
		except:
			self.mcdr_server.logger.exception(self.mcdr_server.tr('console_handler.error'))
	ConsoleHandler.tick = tick

def _mixin_InfoReactorManager_put_info():
	from mcdreforged.info_reactor.info_reactor_manager import InfoReactorManager
	import queue
	def put_info(self, info):
		info.attach_mcdr_server(self.mcdr_server)
		# echo info from the server to the console
		if info.is_from_server:
			if info.content != 'No player was found':
				self.server_logger.info(info.raw_content)
		try:
			self.mcdr_server.task_executor.enqueue_info_task(lambda: self.process_info(info), info.is_user)
		except queue.Full:
			current_time = time.time()
			logging_method = self.mcdr_server.logger.debug
			kwargs = {'option': DebugOption.REACTOR}
			if self.last_queue_full_warn_time is None or current_time - self.last_queue_full_warn_time >= constant.REACTOR_QUEUE_FULL_WARN_INTERVAL_SEC:
				logging_method = self.mcdr_server.logger.warning
				kwargs = {}
				self.last_queue_full_warn_time = current_time
			logging_method(self.mcdr_server.tr('info_reactor_manager.info_queue.full'), **kwargs)
	InfoReactorManager.put_info = put_info

def mixin_mcdr():
	_mixin_ConsoleHandler_tick()
	_mixin_InfoReactorManager_put_info()

#################

def on_load(server :MCDR.ServerInterface, prev_module):
	global SERVER_OBJ, read_write
	SERVER_OBJ = server
	mixin_mcdr()
	if prev_module is None:
		log_info('RawInput is on load')
	else:
		log_info('RawInput is on reload')
		if prev_module.read_write is not None:
			read_write = prev_module.read_write
			# if not prev_module.read_write.closed:
			# 	sys.stdin = open(prev_module.read_write.reader.fileno(), 'r')
			# 	prev_module.read_write.close()
			# 	prev_module.read_write.reader.close()
			# prev_module.read_write = None

	if read_write is None:
		sys_stdin = sys.stdin
		try:
			sys.stdin = read_write = RawReader(os.fdopen(sys_stdin.fileno(), 'r'), sys.stdout, config['prefix'], mixin=True)
		except AssertionError:
			server.logger.error('The input stream are not atty')
		else:
			sys_stdin.close()

#####!!!!!Has some bug
# def on_unload(server :MCDR.ServerInterface):
# 	global SERVER_OBJ, read_write
# 	log_info('RawInput is on unload')
# 	if read_write is not None:
# 		if not read_write.closed:
# 			sys.stdin = open(read_write.reader.fileno(), 'r')
# 			read_write.close()
# 			read_write.reader.close()
# 		read_write = None
# 	if SERVER_OBJ is not None:
# 		SERVER_OBJ = None

# def on_remove(server :MCDR.ServerInterface):
# 	global SERVER_OBJ, read_write
# 	log_info('RawInput is on remove')
# 	if read_write is not None:
# 		if not read_write.closed:
# 			sys.stdin = open(read_write.reader.fileno(), 'r')
# 			read_write.close()
# 			read_write.reader.close()
# 		read_write = None
# 	if SERVER_OBJ is not None:
# 		SERVER_OBJ = None

def on_mcdr_stop(server :MCDR.ServerInterface):
	global SERVER_OBJ, read_write
	log_info('mcdr is on stop')
	if read_write is not None:
		if not read_write.closed:
			read_write.close()
			threading.Thread(target=lambda: os.close(read_write.reader.fileno()), daemon=True).start() # I don't know why it can be blocked
		read_write = None
	log_info('closed')
	if SERVER_OBJ is not None:
		SERVER_OBJ = None
