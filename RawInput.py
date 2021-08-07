
import os
import io
import sys
import threading
import time

IS_WIN32 = os.name == 'win32'

if IS_WIN32:
	import msvcrt
else:
	import tty
	import termios

import mcdreforged.api.all as MCDR
# from mcdreforged.executor.console_handler import ConsoleHandler
# from mcdreforged.info import Info
# from mcdreforged.utils.logger import DebugOption, SyncStreamHandler

PLUGIN_METADATA = {
  'id': 'rawinput',
  'version': '1.0.0',
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
		self._isend = False
		self._helper_thr = None
		self._prefix = prefix
		self._mixin_map = {}
		self._mixin = mixin
		self._old_settings = None
		self._empty_lock = threading.Condition(threading.Lock())
		self._write_lock = threading.Lock()
		self._line_buffer = []
		self.__line_buf = []
		self.__line_index = 0
		assert reader.readable()
		self._reader = reader
		self._reader_fd = self._reader.fileno()
		assert writer.writable()
		self._writer = writer
		self._old_settings = termios.tcgetattr(self._reader_fd)
		try:
			mode = termios.tcgetattr(self._reader_fd)
			mode[tty.IFLAG] &= ~(termios.BRKINT | termios.INPCK | termios.IXON)
			mode[tty.IFLAG] |= termios.ICRNL
			mode[tty.OFLAG] |= termios.BSDLY
			mode[tty.CFLAG] &= ~(termios.CSIZE | termios.PARENB)
			mode[tty.CFLAG] |= termios.CS8
			mode[tty.LFLAG] &= ~(termios.ICANON | termios.ECHO)
			mode[tty.LFLAG] |= termios.ISIG
			mode[tty.CC][termios.VMIN] = 1
			mode[tty.CC][termios.VTIME] = 0
			termios.tcsetattr(self._reader_fd, termios.TCSADRAIN, mode)
			if self._mixin:
				self.__mix(self._reader, 'read')
				self.__mix(self._reader, 'readline')
				self.__mix(self._reader, 'readlines')
				self.__mix(self._writer, 'write')
				self.__mix(self._writer, 'writelines')
		except:
			self.end()
			raise
		self._helper_thr = threading.Thread(target=self.__helper, name='raw-reader(r:{},w:{})'.
			format(self._reader.fileno(), self._writer.fileno()))
		self._helper_thr.setDaemon(True)
		self._helper_thr.start()

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
				if obj not in self._mixin_map:
					self._mixin_map[obj] = {}
				self._mixin_map[obj][key] = old
			setattr(obj, key, new)

	def unload_mixin(self):
		for obj, mmap in self._mixin_map.items():
			for key, old in mmap.items():
				setattr(obj, key, old)

	def _check_end_or_interrupt(self):
		if self._isend:
			raise EOFError()

	def flush(self):
		self._writer.flush()

	def readable(self):
		return True

	def writable(self):
		return True

	def seekable(self):
		return False

	def poll(self):
		self._check_end_or_interrupt()
		return None if len(self._line_buffer) == 0 else self._line_buffer.pop(0)

	def read(self, size=-1):
		try:
			self._check_end_or_interrupt()
			if len(self._line_buffer) == 0:
				with self._empty_lock:
					self._empty_lock.wait()
					self._check_end_or_interrupt()
			data = ''.join(self._line_buffer)
			self._line_buffer.clear()
			return data
		except EOFError:
			pass
		return self.__read(size)

	def readline(self, size=-1):
		self._check_end_or_interrupt()
		if len(self._line_buffer) == 0:
			with self._empty_lock:
				self._empty_lock.wait()
				self._check_end_or_interrupt()
		return self._line_buffer.pop(0)

	def readlines(self, hint=-1):
		self._check_end_or_interrupt()
		if len(self._line_buffer) == 0:
			with self._empty_lock:
				self._empty_lock.wait()
				self._check_end_or_interrupt()
		lines = self._line_buffer
		self._line_buffer.clear()
		return lines

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

	def __readchar(self):
		if IS_WIN32:
			return msvcrt.getch()
		else:
			return self.__read(1)

	def __read(self, size=-1):
		return (self._mixin_map[self._reader]['read'] if self._mixin else self._reader.read)(size)

	def __readline(self, size=-1):
		return (self._mixin_map[self._reader]['readline'] if self._mixin else self._reader.readline)(size)

	def __readlines(self, hint=-1):
		return (self._mixin_map[self._reader]['readlines'] if self._mixin else self._reader.readlines)(size)

	def __write(self, data):
		return (self._mixin_map[self._writer]['write'] if self._mixin else self._writer.write)(data)

	def __helper(self):
		self.__line_buf.clear()
		self.__line_index = 0
		try:
			with self._write_lock:
				self.__write(self._prefix)
				self._writer.flush()
			while not self._isend:
				ch = self.__readchar()
				if self._isend:
					break
				chid = ord(ch)
				if chid == BREAK_ID:
					continue
				with self._write_lock:
					if chid == ESC_ID:
						ch2 = self.__readchar()
						chid2 = ord(ch2)
						if chid2 == MOVE_ID:
							ch3 = self.__readchar()
							chid3 = ord(ch3)
							if chid3 == MOVE_LEFT_ID:
								if self.__line_index > 0:
									self.__line_index -= 1
									self.__write(MOVE_LEFT_CHAR)
							elif chid3 == MOVE_RIGHT_ID:
								if self.__line_index < len(self.__line_buf):
									self.__line_index += 1
									self.__write(MOVE_RIGHT_CHAR)
					elif chid == BACKSPACE_ID:
						if self.__line_index > 0:
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
					elif chid == TAB_ID:
						pass
					elif ch == '\n':
						self.__write(os.linesep)
						self.__write(self._prefix)
						if len(self.__line_buf) > 0:
							with self._empty_lock:
								self._line_buffer.append(''.join(self.__line_buf) + os.linesep)
								self._empty_lock.notify()
						self.__line_buf.clear()
						self.__line_index = 0
					elif ch.isprintable():
						self.__line_buf.insert(self.__line_index, ch)
						self.__line_index += 1
						self.__write(ch)
						if self.__line_index < len(self.__line_buf):
							tail = ''.join(self.__line_buf[self.__line_index:])
							self.__write(tail)
							self.__write(MOVE_LEFT_CHAR * len(tail))
					self._writer.flush()
		except OSError:
			pass
		finally:
			self.end()

	def __enter__(self):
		return self

	def __exit__(self, err_cls, err_msg, traceback):
		self.close_()
		if err_cls is not None and not isinstance(err_cls, EOFError):
			return False
		return True

	def close_rw(self):
		self._reader.close()
		self._writer.close()

	@property
	def closed(self):
		return self._isend

	def close(self):
		pass

	def close_(self):
		self.end()
		if self._helper_thr is not None:
			self._helper_thr = None

	def end(self):
		if self._isend:
			return
		self._isend = True
		self.unload_mixin()
		if self._old_settings:
			termios.tcsetattr(self._reader_fd, termios.TCSADRAIN, self._old_settings)
		with self._empty_lock:
			self._empty_lock.notify_all()


# def _mixin_ConsoleHandler_tick():
# 	def tick(self):
# 		try:
# 			text = ''
# 			while True:
# 				try:
# 					text = read_write.poll()
# 				except (EOFError, OSError, ValueError):
# 					time.sleep(0.05)
# 					continue
# 				if text:
# 					break
# 			parsed_result: Info
# 			try:
# 				parsed_result = self.mcdr_server.server_handler_manager.get_current_handler().parse_console_command(text)
# 			except:
# 				self.mcdr_server.logger.exception(self.mcdr_server.tr('console_handler.parse_fail', text))
# 			else:
# 				if self.mcdr_server.logger.should_log_debug(DebugOption.HANDLER):
# 					self.mcdr_server.logger.debug('Parsed text from {}:'.format(type(self).__name__), no_check=True)
# 					for line in parsed_result.format_text().splitlines():
# 						self.mcdr_server.logger.debug('    {}'.format(line), no_check=True)
# 				self.mcdr_server.reactor_manager.put_info(parsed_result)
# 		except (KeyboardInterrupt, EOFError, SystemExit, IOError) as error:
# 			if self.mcdr_server.is_server_running():
# 				self.mcdr_server.logger.critical('Critical exception caught in {}: {} {}'.format(type(self).__name__, type(error).__name__, error))
# 				self.mcdr_server.interrupt()
# 		except:
# 			self.mcdr_server.logger.exception(self.mcdr_server.tr('console_handler.error'))
# 	ConsoleHandler.tick = tick

#################

def on_load(server :MCDR.ServerInterface, prev_module):
	global SERVER_OBJ, read_write
	SERVER_OBJ = server
	# _mixin_ConsoleHandler_tick()
	if prev_module is not None:
		log_info('RawInput is on reload')
		if prev_module.read_write is not None:
			read_write = prev_module.read_write
			# if not prev_module.read_write.closed:
			# 	sys.stdin = open(prev_module.read_write.reader.fileno(), 'r')
			# 	prev_module.read_write.close()
			# 	prev_module.read_write.reader.close()
			# prev_module.read_write = None
	else:
		log_info('RawInput is on load')
		sys_stdin = sys.stdin
		sys.stdin = read_write = RawReader(os.fdopen(sys_stdin.fileno(), 'r'), sys.stdout, config['prefix'], mixin=True)
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
			read_write.close_()
			threading.Thread(target=lambda: os.close(read_write.reader.fileno()), daemon=True).start() # I don't know why it can be blocked
		read_write = None
	log_info('closed')
	if SERVER_OBJ is not None:
		SERVER_OBJ = None
