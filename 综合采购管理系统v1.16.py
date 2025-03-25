import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import csv
import os
import shutil
import chardet
import tkinter.font as tkFont
from cryptography.fernet import Fernet
import time
import zipfile
import sys
import atexit
import psutil
import portalocker
import bcrypt  # 新增安全密码哈希库

# ==================== 单例检测（保持不变） ====================
def check_single_instance():
    """确保程序只能运行一个实例（跨平台增强版）"""
    lock_path = os.path.join(os.path.expanduser("~"), '.procurement_system.lock')
    
    try:
        # 使用文件锁确保原子操作
        with open(lock_path, 'w') as f:
            portalocker.lock(f, portalocker.LOCK_EX | portalocker.LOCK_NB)
            f.write(f"{os.getpid()}\n")
            f.write(f"启动时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.flush()
            
        # 注册退出清理函数
        def cleanup_lock():
            try:
                if os.path.exists(lock_path):
                    os.remove(lock_path)
            except Exception as e:
                print(f"[DEBUG] 清理锁文件失败: {str(e)}")
                
        atexit.register(cleanup_lock)
        
    except (portalocker.LockException, PermissionError) as e:
        # 读取已有PID
        try:
            with open(lock_path, 'r') as f:
                lines = f.readlines()
                old_pid = int(lines[0].strip()) if lines else None
                
            if old_pid and psutil.pid_exists(old_pid):
                sys.exit(f"错误：{Constants.SOFTWARE_NAME} 已在运行中（PID: {old_pid}）！")
            else:
                print("[DEBUG] 发现残留锁文件，正在清理...")
                try:
                    os.remove(lock_path)
                except Exception as e:
                    print(f"[DEBUG] 清理失败: {str(e)}")
                check_single_instance()  # 递归重试
                
        except Exception as e:
            print(f"[ERROR] 锁文件解析失败: {str(e)}")
            try: 
                os.remove(lock_path)
            except Exception: 
                pass
            sys.exit("检测到无效的锁文件，程序已终止")
            
# ==================== 资源路径处理 ====================
def resource_path(relative_path):
    """ 获取资源的绝对路径，适配打包后的环境 """
    if hasattr(sys, '_MEIPASS'):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
# ==================== 常量管理 ====================
class Constants:
    SOFTWARE_NAME = "综合采购管理系统"
    VERSION = "v1.16"
    MAIN_TITLE = f"{SOFTWARE_NAME} {VERSION}"
    WINDOW_SIZE = "900x815"
    SUPPLIER_COLS = ("供应商名称", "联系人", "电话号码", "通讯地址")
    INVENTORY_LABELS = ["类型*", "名称*", "单位*", "单价*", "备注", "供应商*"]
    FILE_PATHS = {
        'key': "secret.key",
        'suppliers': "suppliers.csv",
        'inventory': "inventory.csv",
        'password': "password.bin"  # 新增密码文件
    }
    OPERATORS = ["包含", "等于", ">", "<"]
# ==================== 加密模块 ====================
class EncryptionManager:
    def __init__(self):
        try:
            self.key = self._load_key()
            if not self.key:
                raise RuntimeError(
                    "未找到密钥文件 secret.key！\n"
                    "请按以下步骤操作：\n"
                    "1. 将 secret.key 文件放置在程序目录下\n"
                    "2. 若您是首次使用，请联系管理员获取密钥文件"
                )
            self.cipher = Fernet(self.key)
        except RuntimeError as e:
            messagebox.showerror("致命错误", str(e))
            sys.exit(1)

    def _load_key(self):
        key_path = resource_path(Constants.FILE_PATHS['key'])
        if not os.path.exists(key_path):
            return None
        try:
            with open(key_path, 'rb') as f:
                return f.read()
        except Exception as e:
            messagebox.showerror("错误", f"密钥加载失败: {e}")
            return None

    def encrypt(self, data):
        return self.cipher.encrypt(data.encode())

    def decrypt(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data).decode()
# ==================== 数据管理 ====================
class DataManager:
    def __init__(self, file_type, encryptor):
        self.file_path = Constants.FILE_PATHS[file_type]
        self.encryptor = encryptor

    def load(self):
        if not os.path.exists(self.file_path):
            return []
        try:
            with open(self.file_path, 'rb') as f:
                return [self.encryptor.decrypt(line).split(',') 
                       for line in f if line]
        except Exception as e:
            messagebox.showerror("错误", f"数据加载失败: {e}")
            return []

    def save(self, data):
        try:
            with open(self.file_path, 'wb') as f:
                for row in data:
                    encrypted_data = self.encryptor.encrypt(','.join(map(str, row)))
                    f.write(encrypted_data + b'\n')
            return True
        except Exception as e:
            messagebox.showerror("错误", f"数据保存失败: {e}")
            return False   
# ==================== 密码管理类 ====================
class PasswordManager:
    def __init__(self):
        self.file_path = Constants.FILE_PATHS['password']
        
    def is_password_set(self):
        """检查是否已设置密码"""
        return os.path.exists(self.file_path)
    
    def verify(self, password):
        """验证密码"""
        if not self.is_password_set():
            return False
        try:
            with open(self.file_path, 'rb') as f:
                hashed = f.read()
            return bcrypt.checkpw(password.encode(), hashed)
        except Exception:
            return False
    
    def set(self, new_password):
        """设置新密码"""
        if len(new_password) < 4:
            raise ValueError("密码至少4位")
        hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        with open(self.file_path, 'wb') as f:
            f.write(hashed)
    
    def clear(self):
        """清除密码"""
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
# ==================== UI组件工厂 ====================
class UIFactory:
    @staticmethod
    def create_frame(parent, **kwargs):
        return tk.Frame(parent, **kwargs)

    @staticmethod
    def create_entry(parent, width=33, bind_func=None):
        entry = tk.Entry(parent, width=width)
        if bind_func:
            entry.bind("<Return>", lambda e: bind_func())
        return entry

    @staticmethod
    def create_button(parent, text, command, width=20):
        return tk.Button(parent, text=text, command=command, width=width)

    @staticmethod
    def create_combobox(parent, values, width=30, readonly=True):
        combo = ttk.Combobox(parent, width=width, values=values)
        if readonly:
            combo.config(state="readonly")
        return combo
# ==================== 供应商管理 ====================
class SupplierManager:
    def __init__(self, master, data_manager, update_callback):
        self.master = master
        self.data_manager = data_manager
        self.update_callback = update_callback
        self.window = None
        self._init_window()

    def _init_window(self):
        self.window = tk.Toplevel(self.master)
        self.window.title("供应商管理")
        self.window.geometry("730x480")
        self.window.resizable(False, False)
        self.window.iconbitmap(resource_path("app_icon.ico"))
        
        self.master.update_idletasks()
        root_x = self.master.winfo_x()
        root_y = self.master.winfo_y()
        root_width = self.master.winfo_width()
        root_height = self.master.winfo_height()
        x = root_x + (root_width - 730) // 2
        y = root_y + (root_height - 480) // 2
        self.window.geometry(f"+{x}+{y}")
        
        self.window.grab_set()
        self.master.attributes('-disabled', True)
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)
        self._create_widgets()
        self.refresh_list()

    def _create_widgets(self):
        self.tree = ttk.Treeview(self.window, columns=Constants.SUPPLIER_COLS, show='headings', height=8, selectmode='extended')
        for col in Constants.SUPPLIER_COLS:
            self.tree.heading(col, text=col, anchor='center')
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.tree.bind("<Configure>", lambda e: self._adjust_columns())
        self.tree.bind("<Double-1>", self._on_cell_click)
        self.tree.bind("<Button-3>", self._show_context_menu)

        input_frame = UIFactory.create_frame(self.window)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        fields = [("供应商名称*", 0, 0), ("联系人", 0, 2),
                 ("电话号码", 1, 0), ("通讯地址", 1, 2)]
        
        self.entries = []
        for text, row, col in fields:
            tk.Label(input_frame, text=text).grid(row=row, column=col, padx=5, pady=2, sticky='w')
            entry = UIFactory.create_entry(input_frame, bind_func=self.add_supplier)
            entry.grid(row=row, column=col+1, padx=5, pady=2, sticky='ew')
            self.entries.append(entry)

        btn_frame = UIFactory.create_frame(self.window)
        btn_frame.pack(pady=10)
        
        buttons = [
            ("添加供应商", self.add_supplier),
            ("删除供应商", self.delete_supplier),
            ("导入供应商数据", self.import_csv),
            ("另存供应商数据", self.export_csv)
        ]
        
        for text, cmd in buttons:
            UIFactory.create_button(btn_frame, text, cmd).pack(side=tk.LEFT, padx=5)
    def _adjust_columns(self):
        font = tkFont.Font()
        for idx, col in enumerate(Constants.SUPPLIER_COLS, start=1):
            max_width = font.measure(col) + 20
            for item in self.tree.get_children():
                cell_value = self.tree.item(item, 'values')[idx-1]
                cell_width = font.measure(str(cell_value)) + 20
                if cell_width > max_width:
                    max_width = cell_width
            self.tree.column(f'#{idx}', width=max_width, anchor='center')

    def refresh_list(self):
        self.tree.delete(*self.tree.get_children())
        for supplier in self.data_manager.load():
            if len(supplier) == 4:
                self.tree.insert("", 'end', values=supplier)
        self._adjust_columns()

    def add_supplier(self):
        fields = [e.get().strip() for e in self.entries]
        name, contact, phone, address = fields
        
        if not name:
            messagebox.showerror("错误", "供应商名称不能为空", parent=self.window)
            return
        if phone and not phone.isdigit():
            messagebox.showerror("错误", "电话号码需为数字", parent=self.window)
            return
        if name in [s[0] for s in self.data_manager.load()]:
            messagebox.showerror("错误", "供应商已存在", parent=self.window)
            return
        
        self.data_manager.save(self.data_manager.load() + [[name, contact, phone, address]])
        self.refresh_list()
        self.update_callback()
        for entry in self.entries:
            entry.delete(0, tk.END)
        messagebox.showinfo("成功", "添加成功", parent=self.window)

    def delete_supplier(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("提示", "请先选择供应商", parent=self.window)
            return
        if messagebox.askyesno("确认", "确定删除选中供应商？", parent=self.window):
            names = [self.tree.item(i, 'values')[0] for i in selected]
            suppliers = [s for s in self.data_manager.load() if s[0] not in names]
            self.data_manager.save(suppliers)
            self.refresh_list()
            self.update_callback()

    def import_csv(self): 
        file_path = filedialog.askopenfilename(
            filetypes=[("CSV files", "*.csv")],
            parent=self.window
        )
        if not file_path:
            return
    
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                encoding = chardet.detect(raw_data)['encoding']
            with open(file_path, 'r', encoding=encoding, errors='replace') as file:
                reader = csv.reader(file)
                imported = []
                for row in reader:
                    if len(row) == 0 or row[0].strip().lower() == "供应商名称":
                        continue
                    imported.append(row)
            existing_suppliers = {s[0] for s in self.data_manager.load()}
            valid_data = []
            for row in imported:
                if len(row) >= 4:
                    name = row[0].strip()
                    contact = row[1].strip() if len(row) > 1 else ""
                    phone = row[2].strip() if len(row) > 2 else ""
                    address = row[3].strip() if len(row) > 3 else ""
                    if name and name not in existing_suppliers:
                        valid_data.append([name, contact, phone, address])
                elif len(row) < 4 and row[0].strip():
                    name = row[0].strip()
                    if name not in existing_suppliers:
                        valid_data.append([name, "", "", ""])
    
            if valid_data:
                self.data_manager.save(self.data_manager.load() + valid_data)
                self.refresh_list()
                self.update_callback()
                messagebox.showinfo(
                    "成功", 
                    f"成功导入 {len(valid_data)} 条数据\n"
                    f"无效数据：{len(imported) - len(valid_data)} 条", 
                    parent=self.window
                )
            else:
                messagebox.showinfo(
                    "提示", 
                    f"无有效数据可导入\n可能原因：\n"
                    "1. 文件列数不足或格式错误\n"
                    "2. 供应商名称已存在\n"
                    "3. 供应商名称为空", 
                    parent=self.window
                )
        except Exception as e:
            messagebox.showerror("错误", f"导入失败: {str(e)}", parent=self.window)

    def export_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not file_path:
            return
        
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as file:
                csv.writer(file).writerows(self.data_manager.load())
            messagebox.showinfo("成功", "导出成功", parent=self.window)
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}", parent=self.window)

    def _on_close(self):
        self.window.grab_release()
        self.master.attributes('-disabled', False)
        self.window.destroy()

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            menu = tk.Menu(self.window, tearoff=0)
            menu.add_command(label="删除此行", command=lambda: self._delete_single_item(item))
            menu.add_separator()
            menu.add_command(label="导入供应商", command=self.import_csv)
            menu.add_command(label="另存供应商", command=self.export_csv)
            menu.post(event.x_root, event.y_root)

    def _delete_single_item(self, item):
        if messagebox.askyesno("确认", "确定删除该供应商？", parent=self.window):
            supplier_name = self.tree.item(item, 'values')[0]
            suppliers = [s for s in self.data_manager.load() if s[0] != supplier_name]
            self.data_manager.save(suppliers)
            self.refresh_list()
            self.update_callback()

    def _on_cell_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        if region not in ("cell", "tree"):
            return

        column = self.tree.identify_column(event.x)
        item = self.tree.identify_row(event.y)
        
        if not item or column == '#0':
            return

        col_idx = int(column[1:]) - 1
        col_name = Constants.SUPPLIER_COLS[col_idx]
        x, y, width, height = self.tree.bbox(item, column)
        current_value = self.tree.item(item, 'values')[col_idx]

        if hasattr(self, '_edit_widget'):
            self._edit_widget.destroy()

        self._edit_widget = tk.Entry(self.tree)
        self._edit_widget.insert(0, current_value)
        self._edit_widget.place(x=x, y=y, width=width, height=height)
        self._edit_widget.focus_set()

        self._edit_widget.bind("<FocusOut>", lambda e: self._save_edit(item, col_idx, col_name))
        self._edit_widget.bind("<Return>", lambda e: self._save_edit(item, col_idx, col_name))

    def _save_edit(self, item, col_idx, col_name):
        new_value = self._edit_widget.get().strip()
        values = list(self.tree.item(item, 'values'))
        
        if col_name == "供应商名称" and not new_value:
            messagebox.showerror("错误", "供应商名称不能为空", parent=self.window)
            return
        if col_name == "电话号码" and not new_value.isdigit():
            messagebox.showerror("错误", "电话号码必须为数字", parent=self.window)
            return
        
        original_name = self.tree.item(item, 'values')[0]
        if col_name == "供应商名称":
            existing_names = [s[0] for s in self.data_manager.load() if s[0] != original_name]
            if new_value in existing_names:
                messagebox.showerror("错误", "供应商名称已存在", parent=self.window)
                return

        suppliers = self.data_manager.load()
        for idx, s in enumerate(suppliers):
            if s[0] == original_name:
                suppliers[idx][col_idx] = new_value
                break
        self.data_manager.save(suppliers)
        
        self._edit_widget.destroy()
        self.refresh_list()
        self.update_callback()
        self.update_row_count()  # 新增行数统计
# ==================== 关于窗口 ====================
class AboutWindow:
    def __init__(self, master):
        self.master = master
        self.window = tk.Toplevel(master)
        self.window.title("关于")
        self.window.geometry("300x165")
        self.window.resizable(False, False)
        self.window.iconbitmap(resource_path("app_icon.ico"))
        
        self.master.update_idletasks()
        root_x = self.master.winfo_x()
        root_y = self.master.winfo_y()
        root_width = self.master.winfo_width()
        root_height = self.master.winfo_height()
        x = root_x + (root_width - 300) // 2
        y = root_y + (root_height - 165) // 2
        self.window.geometry(f"+{x}+{y}")
        
        self.window.grab_set()
        self.master.attributes('-disabled', True)
        self.window.protocol("WM_DELETE_WINDOW", self._on_close)
        self._create_content()

    def _create_content(self):
        content = [
            (Constants.SOFTWARE_NAME, 16, "bold"),
            (f"版本: {Constants.VERSION}", 12),
            ("开发者: 中山市瑞鸿展示科技有限公司", 12),
            ("发布日期: 2025-03-22", 12),
            ("版权: © 2025 All Rights Reserved", 12),
            ("联系邮箱: m13922137615@163.com", 12)
        ]
        
        for i, (text, font_size, *font_style) in enumerate(content):
            font = tkFont.Font(
                size=font_size, 
                weight=font_style[0] if font_style else "normal"
            )
            label = tk.Label(
                self.window, 
                text=text, 
                font=font,
                pady=5 if i == 0 else 2
            )
            label.pack()

    def _on_close(self):
        self.window.grab_release()
        self.master.attributes('-disabled', False)
        self.window.destroy()
# ==================== 进度条对话框 ====================
class ProgressDialog:
    def __init__(self, parent, title="加载中", message="正在加载数据..."):
        self.window = tk.Toplevel(parent)
        self.window.title(title)
        self.window.geometry("300x100")
        self.window.transient(parent)
        self.window.grab_set()
        
        # 居中定位
        parent.update_idletasks()
        root_x = parent.winfo_x()
        root_y = parent.winfo_y()
        x = root_x + (parent.winfo_width() - 300) // 2
        y = root_y + (parent.winfo_height() - 100) // 2
        self.window.geometry(f"+{x}+{y}")
        
        tk.Label(self.window, text=message).pack(pady=5)
        self.progress = ttk.Progressbar(self.window, orient="horizontal", length=250, mode="determinate")
        self.progress.pack(pady=5)
        self.window.protocol("WM_DELETE_WINDOW", lambda: None)  # 禁用关闭按钮
    
    def update(self, value):
        self.progress['value'] = value
        self.window.update()
    
    def close(self):
        self.window.grab_release()
        self.window.destroy()

# ==================== 密码输入窗口 ====================
class PasswordDialog:
    def __init__(self, parent, verify_callback):
        self.window = tk.Toplevel(parent)
        self.window.iconbitmap(resource_path("app_icon.ico"))  # <-- 新增此行
        self.verify_callback = verify_callback
        self.window.title("系统验证")
        self.window.geometry("400x200")
        self.window.resizable(False, False)
        self.window.configure(bg="#F5F5F5")
        
        # ===== 窗口居中逻辑 =====
        screen_width = self.window.winfo_screenwidth()
        screen_height = self.window.winfo_screenheight()
        x = (screen_width - 400) // 2
        y = (screen_height - 200) // 2
        self.window.geometry(f"+{x}+{y}")
        
        # ===== 标题区域 =====
        title_frame = tk.Frame(self.window, bg="#2196F3", height=35)
        title_frame.pack(fill=tk.X)
        
        tk.Label(title_frame,
                text=f"{Constants.SOFTWARE_NAME} {Constants.VERSION}",
                font=("微软雅黑", 10, "bold"),
                fg="white",
                bg="#2196F3"
        ).place(relx=0.5, rely=0.5, anchor="center")
        
        # ===== 主内容区域 =====
        main_frame = tk.Frame(self.window, bg="#F5F5F5", padx=30, pady=15)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 安全提示语
        tk.Label(main_frame,
                text="为确保数据安全，请验证身份",
                font=("微软雅黑", 13),
                bg="#F5F5F5",
                fg="#666666"
        ).pack(pady=(0, 12))
        
        # ===== 输入框（高度基准）=====
        entry_frame = tk.Frame(main_frame, bg="#E0E0E0")
        entry_frame.pack(fill=tk.X, pady=2)
        self.entry = tk.Entry(entry_frame,
                             show="*",
                             font=("微软雅黑", 10),
                             bd=0,
                             relief="flat")
        self.entry.pack(fill=tk.X, ipady=5)  # 关键：通过ipady控制高度
        
        # ===== 按钮区域（与输入框等高）=====
        btn_frame = tk.Frame(main_frame, bg="#F5F5F5")
        btn_frame.pack(fill=tk.X, pady=10)
        
        # 确定按钮
        btn_confirm = tk.Button(btn_frame,
                               text="解锁软件",
                               command=self._verify,
                               bg="#4CAF50",
                               fg="white",
                               activebackground="#45A049",
                               font=("微软雅黑", 10, "bold"),
                               relief="flat",
                               cursor="hand2")
        btn_confirm.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, ipady=6, padx=5)
        
        # 取消按钮
        btn_cancel = tk.Button(btn_frame,
                              text="关闭软件",
                              command=self._safe_destroy,
                              bg="#757575",
                              fg="white",
                              activebackground="#616161",
                              font=("微软雅黑", 10, "bold"),
                              relief="flat",
                              cursor="hand2")
        btn_cancel.pack(side=tk.LEFT, expand=True, fill=tk.BOTH, ipady=6, padx=5)
        
        # 错误提示
        self.lbl_error = tk.Label(main_frame,
                                 text="",
                                 fg="#D32F2F",
                                 bg="#F5F5F5",
                                 font=("微软雅黑", 9))
        self.lbl_error.pack()
        
        # 事件绑定
        self.entry.focus_set()
        self.entry.bind("<Return>", lambda e: self._verify())
        self.window.bind("<Escape>", lambda e: self._safe_destroy())

    def _safe_destroy(self, event=None):
        if self.window.winfo_exists():
            self.window.destroy()

    def _verify(self):
        if self.window.winfo_exists():
            password = self.entry.get()
            if self.verify_callback(password):
                self._safe_destroy()
            else:
                self.entry.delete(0, tk.END)
                self.lbl_error.config(text="密码错误，请重新输入")
                self.entry.focus_set()
# ==================== 主程序 ====================
class ProcurementSystem:
    def __init__(self):
        self.root = tk.Tk()
        self.encryption = EncryptionManager()
        self.supplier_manager = DataManager('suppliers', self.encryption)
        self.inventory_manager = DataManager('inventory', self.encryption)
        self.password_manager = PasswordManager()  # 关键修改：独立密码管理
        self.all_items = []
        self._init_ui()
        self.password_operation_in_progress = False  # 新增操作锁
        # 新增初始化调用
        self.root.after(100, self._show_splash_and_load)  # 延迟100ms确保窗口渲染 
        # ========== 新增退出控制 ==========
        self._running = True
        self.root.protocol("WM_DELETE_WINDOW", self._safe_exit)
    def _on_password_save(self):
        """带锁的密码保存方法"""
        if self.password_operation_in_progress:
            return
            
        try:
            self.password_operation_in_progress = True
            dialog = self.new_pw_entry.winfo_toplevel()
           
        finally:
            self.password_operation_in_progress = False
    

    def _safe_exit(self):
        """安全退出程序"""
        # 分步销毁所有窗口
        try:
            # 1. 销毁所有子窗口
            for child in self.root.winfo_children():
                if isinstance(child, tk.Toplevel):
                    try:
                        child.destroy()
                    except tk.TclError:
                        pass
            
            # 2. 等待窗口关闭完成
            self.root.update_idletasks()
            
            # 3. 销毁主窗口
            if self.root.winfo_exists():
                self.root.destroy()
                
        except tk.TclError as e:
            print(f"安全退出异常: {str(e)}")
        
        # 4. 确保进程退出
        sys.exit(0)
    
    def _show_splash_and_load(self):
        """显示加载进度条"""
        self.progress_dialog = ProgressDialog(self.root)
        self.root.after(50, self._async_load_data)  # 更短延迟确保进度条可见

    def _async_load_data(self):
        """异步加载核心逻辑"""
        try:
            # 阶段1：加载供应商数据
            suppliers = self.supplier_manager.load()
            self.root.after(0, lambda: self.input_entries[5].config(values=[s[0] for s in suppliers]))
            
            # 阶段2：分批次加载库存数据
            inventory_data = self.inventory_manager.load()
            total_items = len(inventory_data)
            batch_size = 300  # 每批插入300条
            
            # 清空现有数据
            self.root.after(0, self.tree.delete, *self.tree.get_children())
            self.all_items.clear()
            
            # 分批次插入和更新进度
            loaded = 0
            for i in range(0, total_items, batch_size):
                batch = inventory_data[i:i+batch_size]
                self.root.after(0, self._insert_batch, batch)
                loaded = min(i + batch_size, total_items)
                progress = (loaded / total_items) * 100
                self.root.after(0, self.progress_dialog.update, progress)
            
            # 最终处理
            self.root.after(0, lambda: [
                self.progress_dialog.close(),
                self._adjust_columns(),
                self.update_row_count(),
                self.root.deiconify()  # 确保主窗口在前
            ])
        except Exception as e:
            self.root.after(0, lambda: [
                self.progress_dialog.close(),
                messagebox.showerror("错误", f"加载失败: {str(e)}", parent=self.root)
            ])

    def _insert_batch(self, batch):
        """插入单批次数据"""
        for item in batch:
            if len(item) == 6:
                item_id = self.tree.insert('', 'end', values=item)
                self.all_items.append(item_id)
        self.tree.update_idletasks()  # 强制更新界面
        
    def _init_ui(self):
        self.root.title(Constants.MAIN_TITLE)
        self.root.geometry(Constants.WINDOW_SIZE)
        self.root.iconbitmap(resource_path("app_icon.ico"))
        
        menubar = tk.Menu(self.root)
        self._create_menu(menubar)
        self.root.config(menu=menubar)
        
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        
        self._create_input_area(main_frame)
        self._create_buttons(main_frame)
        self._create_table(main_frame)
        
        status_bar = tk.Frame(self.root, height=20, bd=1, relief=tk.SUNKEN)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=2, pady=2)
        
        # 左侧信息
        self.selection_info = tk.Label(status_bar, text="当前商品：未选择", anchor='w')
        self.selection_info.pack(side=tk.LEFT, padx=5)

        # 右侧统计信息容器 
        right_stats_frame = tk.Frame(status_bar)
        right_stats_frame.pack(side=tk.RIGHT, padx=5)
        ttk.Separator(right_stats_frame, orient='vertical').pack(side=tk.LEFT, fill='y', padx=5)
        # 数据统计标签（固定在右侧）
        self.lbl_count = tk.Label(right_stats_frame, anchor=tk.E)
        self.lbl_count.pack(side=tk.RIGHT)
        # 初始化统计
        self.update_row_count()
        
        # ========== 新增窗口居中逻辑 ==========
        self.root.update_idletasks()  # 强制更新窗口尺寸
        window_width = self.root.winfo_width()
        window_height = self.root.winfo_height()
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 3  # 垂直位置偏上1/3更美观
        self.root.geometry(f"+{x}+{y}")
        # ========== 新增代码结束 ==========    
        
    def _create_menu(self, menubar):
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="打开加密文件", command=self._import_encrypted)
        file_menu.add_command(label="保存加密文件", command=self._export_encrypted)
        file_menu.add_separator()
        file_menu.add_command(label="另存商品数据", command=self.export_inventory)
        file_menu.add_command(label="导入商品数据", command=self.import_inventory)
        file_menu.add_separator()
        file_menu.add_command(label="退出软件", command=self.root.destroy)
        
        manage_menu = tk.Menu(menubar, tearoff=0)
        manage_menu.add_command(
            label="供应商管理", 
            command=lambda: SupplierManager(self.root, self.supplier_manager, self.update_supplier_combobox)
        )
        manage_menu.add_separator()
        manage_menu.add_command(label="清除所有数据", command=self.clear_all_data)
        
        tool_menu = tk.Menu(menubar, tearoff=0)
        tool_menu.add_command(label="删除选中", command=self.delete_items)
        tool_menu.add_command(label="显示全部", command=self.show_all)
        tool_menu.add_separator()  # 新增
        tool_menu.add_command(label="密码设置", command=self._show_password_settings)  # 新增
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="关于", command=lambda: AboutWindow(self.root))
        
        menubar.add_cascade(label="打开文件", menu=file_menu)
        menubar.add_cascade(label="资料管理", menu=manage_menu)
        menubar.add_cascade(label="工具设置", menu=tool_menu)
        menubar.add_cascade(label="帮助中心", menu=help_menu)
    def _create_input_area(self, parent):
        frame = UIFactory.create_frame(parent)
        frame.pack(fill=tk.X, pady=2)
        
        self.input_entries = []
        for i, text in enumerate(Constants.INVENTORY_LABELS):
            row = i // 3
            col = (i % 3) * 2
            tk.Label(frame, text=text).grid(row=row, column=col, padx=5, pady=2, sticky='w')
            
            if text == "供应商*":
                combo = UIFactory.create_combobox(frame, self._get_suppliers())
                combo.grid(row=row, column=col+1, padx=5, pady=2)
                combo.bind("<Return>", lambda e: self.add_item())
                self.input_entries.append(combo)
            else:
                current_entry = UIFactory.create_entry(frame, bind_func=self.add_item)
                if text == "单位*":
                    validate_func = current_entry.register(lambda text: len(text) <= 2)
                    current_entry.config(validate="key", validatecommand=(validate_func, '%P'))
                elif text == "备注":
                    validate_func = current_entry.register(lambda text: len(text) <= 8)
                    current_entry.config(validate="key", validatecommand=(validate_func, '%P'))
                current_entry.grid(row=row, column=col+1, padx=5, pady=2)
                self.input_entries.append(current_entry)

    def _create_buttons(self, parent):
        frame = UIFactory.create_frame(parent)
        frame.pack(fill=tk.X, pady=5)
        
        left_btn_frame = tk.Frame(frame)
        left_btn_frame.pack(side=tk.LEFT, padx=5)
        
        UIFactory.create_button(left_btn_frame, "一键添加商品", self.add_item, width=18).pack(side=tk.LEFT)
        UIFactory.create_button(left_btn_frame, "删除选中", self.delete_items, width=18).pack(side=tk.LEFT, padx=5)
        search_frame = UIFactory.create_frame(frame)
        search_frame.pack(side=tk.RIGHT, padx=1)
        
        self.col_combo = UIFactory.create_combobox(
            search_frame, 
            values=[l.replace("*","") for l in Constants.INVENTORY_LABELS],
            width=5
        )
        self.col_combo.set("名称")
        self.col_combo.pack(side=tk.LEFT, padx=2)
        
        self.operator_combo = UIFactory.create_combobox(
            search_frame,
            values=Constants.OPERATORS,
            width=5
        )
        self.operator_combo.set("包含")
        self.operator_combo.pack(side=tk.LEFT)
        
        self.value_entry = UIFactory.create_entry(search_frame, width=35, bind_func=self.search_items)
        self.value_entry.pack(side=tk.LEFT, padx=5)
        
        UIFactory.create_button(search_frame, "筛选商品", self.search_items).pack(side=tk.LEFT)
    def _create_table(self, parent):
        # 创建容器框架
        table_frame = tk.Frame(parent)
        table_frame.pack(fill=tk.BOTH, expand=True)
    
        # 创建Treeview组件
        self.tree = ttk.Treeview(
            table_frame, 
            columns=Constants.INVENTORY_LABELS, 
            show='headings', 
            height=10,
            selectmode='extended'
        )
        self.tree.tag_configure('matched', background='#E0F0FF')
    
        # 添加垂直滚动条
        vsb = ttk.Scrollbar(
            table_frame, 
            orient="vertical", 
            command=self.tree.yview
        )
        self.tree.configure(yscrollcommand=vsb.set)
    
        # 布局组件
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
    
        # 配置网格布局权重
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
    
        # 初始化列配置（原有代码保持不变）
        for col in Constants.INVENTORY_LABELS:
            self.tree.heading(col, text=col, anchor='center')
            self.tree.column(col, anchor='center', stretch=True)
    
        # 绑定事件（原有代码保持不变）
        self.tree.bind("<Button-3>", self._show_context_menu)
        self.tree.bind("<Double-1>", self._on_cell_click)
        self._adjust_columns()
        self.tree.bind("<<TreeviewSelect>>", self._update_selection_info)
        # 绑定鼠标事件（在原有绑定基础上新增）
        self.tree.bind("<Button-1>", self._handle_left_click)  # 处理左键点击
        self.tree.bind("<Control-Button-1>", self._handle_ctrl_click)  # 处理Ctrl+左键
        
    def _handle_left_click(self, event):
        """处理普通左键点击"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)  # 单选模式

    def _handle_ctrl_click(self, event):
        """处理Ctrl+左键多选"""
        item = self.tree.identify_row(event.y)
        if item:
            current_selection = list(self.tree.selection())
            if item in current_selection:
                current_selection.remove(item)  # 取消选择
            else:
                current_selection.append(item)   # 添加选择
            self.tree.selection_set(current_selection)  # 更新选中项
         
    # 新增事件处理方法
    def _update_selection_info(self, event=None):
        """更新选中商品信息"""
        selected = self.tree.selection()
        if not selected:
            self.selection_info.config(text="当前商品：未选择")
            return
    
        # 获取第一个选中项的数据
        item = selected[0]
        values = self.tree.item(item, 'values')
    
        # 提取名称和单价（索引1和3）
        name = values[1] if len(values) > 1 else ""
        price = values[3] if len(values) > 3 else ""
    
        # 格式化显示
        info_text = f"当前商品：{name} | 单价：{price}元"
        self.selection_info.config(text=info_text)

    def _adjust_columns(self):
        font = tkFont.Font()
        for col in Constants.INVENTORY_LABELS:
            max_width = font.measure(col) + 20
            for item in self.tree.get_children():
                cell_value = self.tree.item(item, 'values')[Constants.INVENTORY_LABELS.index(col)]
                cell_width = font.measure(str(cell_value)) + 20
                if cell_width > max_width:
                    max_width = cell_width
            self.tree.column(col, width=max_width)

    # def _auto_load_data(self):
        # try:
            # supplier_names = [s[0] for s in self.supplier_manager.load()]
            # self.input_entries[5]['values'] = supplier_names
            
            # self.tree.delete(*self.tree.get_children())
            # self.all_items = []
            # for item in self.inventory_manager.load():
                # if len(item) == 6:
                    # item_id = self.tree.insert('', 'end', values=item)
                    # self.all_items.append(item_id)
            # self._adjust_columns()
            # self.update_row_count()  # 新增行数统计
        # except Exception as e:
            # messagebox.showerror("错误", f"自动加载失败: {str(e)}", parent=self.root)

    def _get_suppliers(self):
        return [s[0] for s in self.supplier_manager.load()]

    def update_supplier_combobox(self):
        self.input_entries[5]['values'] = self._get_suppliers()

    def _get_existing_item_keys(self):
        """获取所有商品的六列唯一标识集合（类型、名称、单位、单价、备注、供应商），单价统一格式化为两位小数"""
        return {
            (
                self.tree.item(item)['values'][0],  # 类型
                self.tree.item(item)['values'][1],  # 名称
                self.tree.item(item)['values'][2],  # 单位
                f"{float(self.tree.item(item)['values'][3]):.2f}",
                self.tree.item(item)['values'][4],  # 备注
                self.tree.item(item)['values'][5]   # 供应商
            )
            for item in self.all_items
        }

    def add_item(self):
        fields = [e.get().strip() if isinstance(e, tk.Entry) else e.get() 
                 for e in self.input_entries[:6]]

        # ==== 数据验证逻辑 ====
        if not all([fields[0], fields[1], fields[2], fields[5]]):
            messagebox.showerror("错误", "带*字段不能为空", parent=self.root)
            return

        # ==== 新增：单价格式化为两位小数 ====
        try:
            price = float(fields[3])
            if price < 0:
                raise ValueError
            formatted_price = f"{price:.2f}"  # 格式化为两位小数
        except ValueError:
            messagebox.showerror("错误", "单价必须为数字", parent=self.root)
            return

        # 更新单价字段为格式化后的值
        fields[3] = formatted_price

        # ==== 校验供应商是否存在 ====
        if fields[5] not in self._get_suppliers():
            messagebox.showerror("错误", "供应商不存在，请先在供应商管理中维护", parent=self.root)
            return

        # ==== 生成唯一键并校验重复 ====
        new_key = (
            fields[0],          # 类型
            fields[1],          # 名称
            fields[2],          # 单位
            formatted_price,    # 单价（两位小数）
            fields[4],          # 备注
            fields[5]           # 供应商
        )
        existing_keys = self._get_existing_item_keys()
        if new_key in existing_keys:
            messagebox.showerror("错误", "完全相同的商品数据已存在", parent=self.root)
            return

        # ==== 插入表格并保存 ====
        item_id = self.tree.insert('', 'end', values=fields)
        self.all_items.append(item_id)
        self._save_inventory()
        self._clear_inputs()
        self.tree.see(item_id)
        self.tree.selection_set(item_id)
        self._adjust_columns()
        self.update_row_count()  # 新增行数统计
        self.tree.update_idletasks()

    def delete_items(self):
        """删除选中项（带有效性校验）"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("提示", "请先选择要删除的行", parent=self.root)
            return
    
        # 获取实际存在的待删除项
        valid_items = [item for item in selected if item in self.all_items]
    
        if not valid_items:
            messagebox.showwarning("警告", "选中项不存在于数据源中", parent=self.root)
            return

        confirm = messagebox.askyesno(
            "确认删除", 
            f"确定要删除选中的 {len(valid_items)} 项数据吗？", 
            parent=self.root
        )
        if confirm:
            try:
                # 删除数据源项
                for item in valid_items:
                    self.all_items.remove(item)
                
                # 批量删除界面项
                self.tree.delete(*selected)
            
                # 更新状态
                self._save_inventory()
                self._adjust_columns()
                self.update_row_count()
                self._update_selection_info()
            
            except ValueError as e:
                messagebox.showerror("错误", f"删除失败: {str(e)}", parent=self.root)
                # self._auto_load_data()  # 重新加载数据恢复一致性

    def search_items(self):
        self.root.config(cursor="watch")
        self.root.update()
        
        for item in self.all_items:
            self.tree.reattach(item, '', 'end')
        
        col = self.col_combo.get().strip()
        operator = self.operator_combo.get().strip()
        value = self.value_entry.get().strip()
        
        if not all([col, operator, value]):
            messagebox.showwarning("提示", "请填写完整筛选条件", parent=self.root)
            self.root.config(cursor="")
            return

        try:
            clean_labels = [l.replace("*","") for l in Constants.INVENTORY_LABELS]
            col_idx = clean_labels.index(col)
            original_label = Constants.INVENTORY_LABELS[col_idx]
        except ValueError:
            messagebox.showerror("错误", "无效的列名", parent=self.root)
            self.root.config(cursor="")
            return
        
        for item in self.all_items:
            row_data = self.tree.item(item)['values']
            cell_value = str(row_data[col_idx])
            
            if original_label in ["单价*"]:
                try:
                    cell_num = float(cell_value)
                    filter_num = float(value)
                    if operator == ">":
                        condition = cell_num > filter_num
                    elif operator == "<":
                        condition = cell_num < filter_num
                    elif operator == "等于":
                        condition = cell_num == filter_num
                    else:
                        condition = False
                except ValueError:
                    condition = False
            else:
                cell_value = cell_value.lower()
                target_value = value.lower()
                if operator == "包含":
                    condition = target_value in cell_value
                elif operator == "等于":
                    condition = cell_value == target_value
                else:
                    condition = False
            
            if not condition:
                self.tree.detach(item)
        
        self.root.config(cursor="")

    def show_all(self):
        for item in self.all_items:
            self.tree.reattach(item, '', 'end')
        self._adjust_columns()
        self.update_row_count()  # 新增行数统计
        self._update_selection_info()
        self.tree.reattach(item, '', 'end')  # 恢复显示
        self.update_row_count()              # 显示数=总数
        
    def import_inventory(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("CSV files", "*.csv")],
            parent=self.root
        )
        if not file_path:
            return

        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                encoding = chardet.detect(raw_data)['encoding']
    
            with open(file_path, 'r', encoding=encoding, errors='replace') as file:
                reader = csv.reader(file)
                imported = []
                for row in reader:
                    if len(row) == 0 or row[0].strip().lower() == "类型":
                        continue
                    imported.append(row)

            valid_count = 0
            existing_keys = self._get_existing_item_keys()
        
            for row in imported:
                if len(row) < 6:
                    continue
                try:
                    type_ = row[0].strip()
                    name = row[1].strip()
                    unit = row[2].strip()
                 
                    # ========== 修改点1：单价格式化 ==========
                    try:
                        price = f"{float(row[3].strip()):.2f}"  # 强制两位小数
                    except ValueError:
                        continue  # 单价无效则跳过
                
                    note = row[4].strip() if len(row) > 4 else ""
                    supplier = row[5].strip()
        
                    if not all([name, unit, supplier]):
                        continue
                
                    # ========== 修改点2：生成格式化后的item_key ==========
                    item_key = (
                        type_,    # 类型
                        name,     # 名称
                        unit,     # 单位
                        price,    # 单价（两位小数）
                        note,     # 备注
                        supplier  # 供应商
                    )
                
                    if item_key in existing_keys:
                        continue
                    item_id = self.tree.insert('', 'end', values=(type_, name, unit, price, note, supplier))
                    self.all_items.append(item_id)
                    valid_count += 1
                    existing_keys.add(item_key)
                except (ValueError, IndexError):
                    continue

            if valid_count > 0:
                self._save_inventory()
                self._adjust_columns()
                self.update_row_count()  # 新增行数统计
                self._update_selection_info()
                messagebox.showinfo(
                    "成功", 
                    f"成功导入 {valid_count} 条数据\n无效数据：{len(imported) - valid_count} 条", 
                    parent=self.root
                )
            else:
                messagebox.showinfo(
                    "提示", 
                    "无有效数据可导入\n可能原因：\n"
                    "1. 文件列数不足或格式错误\n"
                    "2. 六列数据完全重复\n"
                    "3. 必填字段为空或单价无效", 
                    parent=self.root
                )
        except Exception as e:
            messagebox.showerror("错误", f"导入失败: {str(e)}", parent=self.root)
            

    def export_inventory(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not file_path:
            return
        
        try:
            data = [self.tree.item(item)['values'] for item in self.tree.get_children()]
            with open(file_path, 'w', newline='', encoding='utf-8') as file:
                csv.writer(file).writerows(data)
            messagebox.showinfo("成功", "导出成功", parent=self.root)
        except Exception as e:
            messagebox.showerror("错误", f"导出失败: {e}", parent=self.root)

    def _export_encrypted(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".zip",
            filetypes=[("ZIP Files", "*.zip")]
        )
        if file_path:
            try:
                files_to_export = [
                    Constants.FILE_PATHS['inventory'],
                    Constants.FILE_PATHS['suppliers'],
                    Constants.FILE_PATHS['key']
                ]
                with zipfile.ZipFile(file_path, 'w') as zipf:
                    for file in files_to_export:
                        if os.path.exists(file):
                            zipf.write(file, os.path.basename(file))
                messagebox.showinfo("成功", "加密数据包已导出", parent=self.root)
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {e}", parent=self.root)

    def _import_encrypted(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("ZIP Files", "*.zip")]
        )
        if not file_path:
            return
    
        # 新增进度条
        progress = ProgressDialog(self.root, "导入加密文件", "正在解密并加载数据...")
        self.root.after(100, self._async_import_data, file_path, progress)

    def _async_import_data(self, file_path, progress):
        """异步导入加密数据的核心逻辑"""
        try:
            # 阶段1：解压文件
            with zipfile.ZipFile(file_path, 'r') as zipf:
                zipf.extractall('.')
        
            # 阶段2：加载供应商数据
            supplier_data = self.supplier_manager.load()
            self.root.after(0, lambda: self.input_entries[5].config(values=[s[0] for s in supplier_data]))
        
            # 阶段3：分批次加载库存数据
            inventory_data = self.inventory_manager.load()
            total = len(inventory_data)
            batch_size = 300
        
            # 清空现有数据
            self.root.after(0, self.tree.delete, *self.tree.get_children())
            self.all_items.clear()
        
            # 分批次插入
            for i in range(0, total, batch_size):
                batch = inventory_data[i:i+batch_size]
                progress_val = (i + batch_size) / total * 100
                self.root.after(0, self._insert_import_batch, batch, progress, progress_val)
        
            # 完成操作
            self.root.after(0, lambda: [
                progress.close(),
                self._adjust_columns(),
                self.update_row_count(),
                messagebox.showinfo("成功", "加密数据包已导入", parent=self.root)
            ])
        except Exception as e:
            self.root.after(0, lambda: [
                progress.close(),
                messagebox.showerror("错误", f"导入失败: {str(e)}", parent=self.root)
            ])

    def _insert_import_batch(self, batch, progress, progress_val):
        """插入导入数据的单批次"""
        for item in batch:
            if len(item) == 6:
                item_id = self.tree.insert('', 'end', values=item)
                self.all_items.append(item_id)
        progress.update(progress_val)
        self.tree.update_idletasks()  # 强制界面更新

    def _save_inventory(self):
        data = [self.tree.item(item)['values'] for item in self.all_items]
        self.inventory_manager.save(data)
        

    def update_row_count(self):
        """更新数据统计（总数固定为总数据量）"""
        total = len(self.all_items)          # 总数始终基于所有数据
        visible = len(self.tree.get_children(''))  # 显示数基于当前可见条目
        self.lbl_count.config(text=f"商品总数: {total} 条 | 当前显示: {visible}条")

    def search_items(self):
        """筛选商品（关键修改：仅隐藏不删除）"""
        self.root.config(cursor="watch")
        self.root.update()

        # 先显示所有条目再筛选
        for item in self.all_items:
            self.tree.reattach(item, '', 'end')

        # 获取筛选条件
        col = self.col_combo.get().strip()
        operator = self.operator_combo.get().strip()
        value = self.value_entry.get().strip()

        if not all([col, operator, value]):
            messagebox.showwarning("提示", "请填写完整筛选条件", parent=self.root)
            self.root.config(cursor="")
            return

        try:
            # 获取列索引（兼容带*的标签）
            clean_labels = [l.replace("*","") for l in Constants.INVENTORY_LABELS]
            col_idx = clean_labels.index(col)
            original_label = Constants.INVENTORY_LABELS[col_idx]
        except ValueError:
            messagebox.showerror("错误", "无效的列名", parent=self.root)
            self.root.config(cursor="")
            return

        # 筛选逻辑
        for item in self.all_items:
            row_data = self.tree.item(item, 'values')
            cell_value = str(row_data[col_idx])

            # 数值类型特殊处理
            if original_label in ["单价*"]:
                try:
                    cell_num = float(cell_value)
                    filter_num = float(value)
                    condition = {
                        ">": cell_num > filter_num,
                        "<": cell_num < filter_num,
                        "等于": cell_num == filter_num
                    }.get(operator, False)
                except ValueError:
                    condition = False
            else:
                # 文本类型处理
                cell_value = cell_value.lower()
                target_value = value.lower()
                condition = {
                    "包含": target_value in cell_value,
                    "等于": cell_value == target_value
                }.get(operator, False)

            # 隐藏不符合条件的条目
            if not condition:
                self.tree.detach(item)  # 关键修改：使用detach代替delete

        self.root.config(cursor="")
        self.update_row_count()  # 更新统计

    def show_all(self):
        """显示全部商品（恢复隐藏项）"""
        for item in self.all_items:
            self.tree.reattach(item, '', 'end')  # 恢复所有隐藏项
        self._adjust_columns()
        self.update_row_count()
   
    def _clear_inputs(self):
        for e in self.input_entries[:6]:
            if isinstance(e, tk.Entry):
                e.delete(0, tk.END)
            else:
                e.set('')

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            # 如果当前点击项未被选中，则更新选中状态
            if item not in self.tree.selection():
                self.tree.selection_set(item)
            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(
                label=f"删除选中({len(self.tree.selection())}项)", 
                command=self.delete_items
            )
            menu.add_command(label="显示全部", command=self.show_all)
            menu.add_separator()
            menu.add_command(label="另存商品", command=self.export_inventory)
            menu.add_command(label="导入商品", command=self.import_inventory)
            menu.post(event.x_root, event.y_root)
            

    def _delete_single_item(self, item):
        if not item:
            messagebox.showwarning("提示", "未选择有效行", parent=self.root)
            return
        if messagebox.askyesno("确认", "确定删除此行？", parent=self.root):
            if item in self.all_items:
                self.all_items.remove(item)
            self.tree.delete(item)
            self._save_inventory()
            self.update_row_count()  # 新增行数统计

    def _on_cell_click(self, event):
        region = self.tree.identify_region(event.x, event.y)
        if region not in ("cell", "tree"):
            return

        column = self.tree.identify_column(event.x)
        item = self.tree.identify_row(event.y)
        
        if not item or column == '#0':
            return

        col_idx = int(column[1:]) - 1
        col_name = Constants.INVENTORY_LABELS[col_idx]
        if col_name == "供应商*":
            return

        x, y, width, height = self.tree.bbox(item, column)
        current_value = self.tree.item(item, 'values')[col_idx]

        if hasattr(self, '_edit_widget'):
            self._edit_widget.destroy()

        self._edit_widget = tk.Entry(self.tree)
        self._edit_widget.insert(0, current_value)
        self._edit_widget.place(x=x, y=y, width=width, height=height)
        self._edit_widget.focus_set()

        self._edit_widget.bind("<FocusOut>", lambda e: self._save_edit(item, col_idx))
        self._edit_widget.bind("<Return>", lambda e: self._save_edit(item, col_idx))

    def _save_edit(self, item, col_idx):
        new_value = self._edit_widget.get().strip()
        values = list(self.tree.item(item, 'values'))
        col_name = Constants.INVENTORY_LABELS[col_idx]
    
        # ==== 字段校验 ====
        if col_name in ["类型*", "名称*", "单位*", "供应商*"] and not new_value:
            messagebox.showerror("错误", "带*字段不能为空", parent=self.root)
            return
        if col_name == "单位*":
            new_value = new_value[:2]
        elif col_name == "备注":
            new_value = new_value[:8]
        if col_name == "单价*":
            try:
                new_value = f"{float(new_value):.2f}"  # 强制两位小数
            except ValueError:
                messagebox.showerror("错误", "单价必须为数字", parent=self.root)
                return
    
        # ==== 更新值并生成唯一键 ====
        values[col_idx] = new_value
        try:
            formatted_price = f"{float(values[3]):.2f}"  # 确保单价格式统一
        except ValueError:
            formatted_price = "0.00"
        new_key = (
            values[0],          # 类型
            values[1],          # 名称
            values[2],          # 单位
            formatted_price,    # 单价（两位小数）
            values[4],          # 备注
            values[5]           # 供应商
        )
    
        # ==== 排除自身后校验重复 ====
        existing_keys = self._get_existing_item_keys()
        current_item_key = (
            self.tree.item(item)['values'][0],
            self.tree.item(item)['values'][1],
            self.tree.item(item)['values'][2],
            f"{float(self.tree.item(item)['values'][3]):.2f}",
            self.tree.item(item)['values'][4],
            self.tree.item(item)['values'][5]
        )
        existing_keys.discard(current_item_key)  # 排除当前条目自身
      
        if new_key in existing_keys:
            messagebox.showerror("错误", "修改后的数据与其他条目完全重复", parent=self.root)
            return
    
        # ==== 保存修改 ====
        self.tree.item(item, values=values)
        self._edit_widget.destroy()
        self._save_inventory()
        self._adjust_columns()
    #添加密码设置功能方法
    def _show_password_settings(self):
        """密码设置对话框"""
        dialog = tk.Toplevel(self.root)
        dialog.title("密码设置")
        dialog.geometry("250x150")
        dialog.resizable(False, False)  # 禁止调整窗口大小
        
        # ===== 窗口居中逻辑 =====
        dialog.update_idletasks()  # 强制更新窗口尺寸
        main_x = self.root.winfo_x()
        main_y = self.root.winfo_y()
        main_width = self.root.winfo_width()
        main_height = self.root.winfo_height()
        dialog_width = 250
        dialog_height = 150
        x = main_x + (main_width - dialog_width) // 2
        y = main_y + (main_height - dialog_height) // 2
        dialog.geometry(f"+{x}+{y}")
        
        # 组件定义
        old_pw_var = tk.StringVar()
        new_pw_var = tk.StringVar()
        confirm_pw_var = tk.StringVar()
        
        # 当前密码输入（仅当已设置密码时显示）
        if self.password_manager.is_password_set():
            tk.Label(dialog, text="当前密码:").grid(row=0, padx=10, pady=5, sticky='e')
            tk.Entry(dialog, textvariable=old_pw_var, show="*").grid(row=0, column=1, padx=10)
        
        # 新密码输入
        tk.Label(dialog, text="新密码:").grid(row=1, padx=10, pady=5, sticky='e')
        tk.Entry(dialog, textvariable=new_pw_var, show="*").grid(row=1, column=1, padx=10)
        
        # 确认密码
        tk.Label(dialog, text="确认密码:").grid(row=2, padx=10, pady=5, sticky='e')
        tk.Entry(dialog, textvariable=confirm_pw_var, show="*").grid(row=2, column=1, padx=10)
        
        # 操作按钮
        def on_save():
            old_pw = old_pw_var.get().strip()
            new_pw = new_pw_var.get().strip()
            confirm_pw = confirm_pw_var.get().strip()
            
            # 修改密码验证
            if self.password_manager.is_password_set():
                if not self.password_manager.verify(old_pw):
                    messagebox.showerror("错误", "当前密码错误", parent=dialog)
                    return
                    
            # 设置新密码
            if new_pw:
                if new_pw != confirm_pw:
                    messagebox.showerror("错误", "两次输入不一致", parent=dialog)
                    return
                try:
                    self.password_manager.set(new_pw)
                    messagebox.showinfo("成功", "密码已更新", parent=dialog)
                    dialog.destroy()
                except Exception as e:
                    messagebox.showerror("错误", str(e), parent=dialog)
            
            # 清除密码
            else:
                if messagebox.askyesno("确认", "确定要取消密码保护吗？", parent=dialog):
                    self.password_manager.clear()
                    messagebox.showinfo("成功", "已取消密码", parent=dialog)
                    dialog.destroy()

        tk.Button(dialog, text="保存", command=on_save).grid(row=3, columnspan=2, pady=5)

    def clear_all_data(self):
        if messagebox.askyesno("警告", "将永久删除所有供应商和库存数据！\n确定继续吗？", parent=self.root):
            # ==== 新增：直接清空界面数据 ====
            self.tree.delete(*self.tree.get_children())  # 删除所有表格行
            self.all_items.clear()                      # 清空内存数据
            # ==== 原有数据持久化操作 ====
            self.supplier_manager.save([])
            self.inventory_manager.save([])
            # ==== 新增：立即更新界面状态 ====
            self._adjust_columns()
            self.update_row_count()
            self._update_selection_info()
            # ==== 优化提示框显示时机 ====
            self.root.after(100, lambda: messagebox.showinfo("完成", "所有数据已清空", parent=self.root))
               

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    # ===== 跨平台DPI适配 =====
    if sys.platform.startswith('win'):
        from ctypes import windll
        try:
            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

    check_single_instance()
    
    # ===== 密码验证流程 =====
    password_manager = PasswordManager()
    if password_manager.is_password_set():
        temp_root = tk.Tk()
        temp_root.withdraw()
        
        def verify(password):
            if password_manager.verify(password):
                temp_root.after(100, temp_root.destroy)  # 延迟销毁避免竞态
                return True
            return False
            
        PasswordDialog(temp_root, verify)
        temp_root.mainloop()
    
    # ===== 主程序启动 =====
    app = ProcurementSystem()
    try:
        app.run()
    except Exception as e:
        print(f"致命错误: {str(e)}")
        app._safe_exit()
