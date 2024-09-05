/**
 * @author nawww83@gmail.com
 */

#include "widget.h"
#include "./ui_widget.h"

#include <QMessageBox>
#include <QMenu>
#include <QContextMenuEvent>
#include <QIcon>
#include <QClipboard>
#include <QItemDelegate>
#include <QFile>
#include <QStringEncoder>

#include <random> // std::random_device

#include "utils.h"

static constexpr auto VERSION = "#v1.00";

namespace {
    const auto gen_pass_txt = QString::fromUtf8("Insert a row with a new password");
    MyTextEdit* txt_edit_master_phrase = nullptr;
    QTableWidgetItem* selected_context_item = nullptr;
    constexpr int num_of_passwords = 10; // in pswd_buff.
    constexpr int password_len_per_request = 10; // 64 bit = 2*32 = 2*5 ascii94 symbols.
    int password_len;
    constexpr int pswd_column_idx = 1;
    const char* asterics {"*************"};
    namespace symbols {
        const auto end_message = QChar(0x0003);
        const auto empty_item = QChar(0x0008);
        const auto row_delimiter = QChar(0x001E);
        const auto col_delimiter = QChar(0x001F);
    }
}

static void RequestPasswords(QFutureWatcher<QVector<lfsr8::u64>>& watcher) {
    const int Nw = (password_len * num_of_passwords) / password_len_per_request + 1;
    watcher.setFuture( main::worker.gen_n(std::ref(main::pass_gen), Nw) );
    watcher.waitForFinished();
    main::pswd_buff = watcher.result();
}

class PassEditDelegate : public QItemDelegate
{
public:
    explicit PassEditDelegate(QObject* parent = nullptr)
        : QItemDelegate(parent)
    {}
    void setEditorData(QWidget *editor, const QModelIndex &index) const {
        QVariant value = index.model()->data(index, Qt::UserRole);
        QLineEdit * edit = qobject_cast<QLineEdit *>(editor);
        if (edit) {
            edit->setText(value.toString());
        } else {
            QItemDelegate::setEditorData(editor, index);
        }
    }
    void setModelData(QWidget *editor, QAbstractItemModel *model, const QModelIndex &index) const {
        QLineEdit * edit = qobject_cast<QLineEdit *>(editor);
        if (edit) {
            const QString value = edit->text();
            model->setData(index, asterics, Qt::DisplayRole);
            model->setData(index, value, Qt::UserRole);
        } else {
            QItemDelegate::setModelData(editor, model, index);
        }
    }
};


Widget::Widget(QString&& pin, QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    {
        QString mPin {pin};
        main::pin_code[0] = mPin[0].digitValue();
        main::pin_code[1] = mPin[1].digitValue();
        main::pin_code[2] = mPin[2].digitValue();
        main::pin_code[3] = mPin[3].digitValue();
        #pragma optimize( "", off )
        for (auto& el : mPin) {
            el = '\0';
        }
        #pragma optimize( "", on )
    }
    ui->setupUi(this);
    QString title = "AllPass 128-bit ";
    QString version = QString(VERSION).remove("#");
    title.append(version);
    title.append(QString(" - Password Manager"));
    this->setWindowTitle( title );

    txt_edit_master_phrase = new MyTextEdit();
    txt_edit_master_phrase->setWindowTitle("Master phrase input");
    txt_edit_master_phrase->setStyleSheet("color: white; background-color: black; font: 14px;");
    txt_edit_master_phrase->setVisible(false);

    connect(txt_edit_master_phrase, &MyTextEdit::sig_closing, this, &Widget::update_master_phrase);
    connect(this, &Widget::master_phrase_ready, this, &Widget::set_master_key);

    password_len = ui->spbx_pass_len->value();

    ui->btn_generate->setText(gen_pass_txt);
    ui->btn_generate->setEnabled(false);
    ui->btn_add_empty_row->setEnabled(false);

    ui->tableWidget->setSortingEnabled(false);
    QStringList table_header {"Login","Password","Comments"};
    ui->tableWidget->setHorizontalHeaderLabels(table_header);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setColumnWidth(0, 200);
    ui->tableWidget->setColumnWidth(1, 200);
    ui->tableWidget->setColumnWidth(2, 370);
    PassEditDelegate* pass_delegate = new PassEditDelegate(this);
    ui->tableWidget->setItemDelegateForColumn(pswd_column_idx, pass_delegate);
    ui->tableWidget->installEventFilter(this);
    ui->tableWidget->setEditTriggers(QAbstractItemView::DoubleClicked);
    ui->tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->tableWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableWidget->horizontalHeader()->setStretchLastSection(true);
    connect(ui->tableWidget, &QTableWidget::customContextMenuRequested, this, &Widget::tableWidget_customContextMenuRequested);
    copyAct = new QAction(QIcon(),
                         tr("&Copy to the clipboard"), this);
    copyAct->setShortcuts(QKeySequence::Copy);
    copyAct->setStatusTip(tr("Copy the item to the clipboard"));
    connect(copyAct, &QAction::triggered, this, &Widget::copy_clipboard);
    removeAct = new QAction(QIcon(),
                          tr("&Delete the row"), this);
    removeAct->setShortcuts(QKeySequence::Delete);
    removeAct->setStatusTip(tr("Delete the current row"));
    connect(removeAct, &QAction::triggered, this, &Widget::delete_row);
    updatePassAct = new QAction(QIcon(),
                                tr("&Change the password"), this);
    updatePassAct->setStatusTip(tr("Change the password to a new one"));
    connect(updatePassAct, &QAction::triggered, this, &Widget::update_pass);

    connect(&watcher_seed_pass_gen, &QFutureWatcher<lfsr_rng::Generators>::finished, this, &Widget::seed_pass_has_been_set);

    ui->btn_input_master_phrase->setFocus();
}

Widget::~Widget()
{
    save_to_store();
    delete ui;
}

bool Widget::eventFilter(QObject *object, QEvent *event)
{
    static bool foundCopy = false;
    if (event->type() == QEvent::KeyPress)
    {
        QKeyEvent* pKeyEvent = static_cast<QKeyEvent*>(event);
        if (pKeyEvent->matches(QKeySequence::Copy))
        {
            foundCopy = true;
            return true;
        }
        else
        {
            foundCopy = false;
        }
        if (pKeyEvent->key() == Qt::Key_Delete && ui->tableWidget->hasFocus())
        {
            QMessageBox mb;
            mb.setInformativeText(QString::fromUtf8("Do you want to remove the row?"));
            mb.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
            mb.setDefaultButton(QMessageBox::No);
            int ret = mb.exec();
            if (ret != QMessageBox::Yes) {
                return false;
            }
            const int row = ui->tableWidget->currentRow();
            ui->tableWidget->removeRow(row);
            return true;
        }
    }
    if (event->type() == QEvent::KeyRelease)
    {
        QKeyEvent* pKeyEvent = static_cast<QKeyEvent*>(event);
        if (foundCopy)
        {
            selected_context_item = ui->tableWidget->currentItem();
            copy_clipboard();
            foundCopy = false;
            return true;
        }
        if (pKeyEvent->matches(QKeySequence::Copy))
        {
            return true;
        }
    }
    return QWidget::eventFilter(object, event);
}

void Widget::copy_clipboard() {
    if (!selected_context_item) {
        return;
    }
    QClipboard * clipboard = QApplication::clipboard();
    if (selected_context_item->column() == pswd_column_idx) {
        clipboard->setText(selected_context_item->data(Qt::UserRole).toString());
    } else {
        clipboard->setText(selected_context_item->text());
    }
    selected_context_item = nullptr;
}

void Widget::delete_row() {
    QMessageBox mb;
    mb.setInformativeText(QString::fromUtf8("Do you want to remove the row?"));
    mb.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    mb.setDefaultButton(QMessageBox::No);
    int ret = mb.exec();
    if (ret != QMessageBox::Yes) {
        return;
    }
    if (!selected_context_item) {
        const int row = ui->tableWidget->currentRow();
        ui->tableWidget->removeRow(row);
        return;
    }
    ui->tableWidget->removeRow(selected_context_item->row());
    selected_context_item = nullptr;
}

void Widget::update_pass() {
    if (!selected_context_item) {
        return;
    }
    if (selected_context_item->column() == pswd_column_idx) {
        if (!selected_context_item->data(Qt::UserRole).toString().isEmpty()) {
            QMessageBox mb;
            mb.setInformativeText(QString::fromUtf8("Do you really want to replace the current password by a new one?"));
            mb.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
            mb.setDefaultButton(QMessageBox::No);
            int ret = mb.exec();
            if (ret != QMessageBox::Yes) {
                return;
            }
        }
        QString pswd = utils::GetPassword(password_len);
        if (pswd.length() < password_len) {
            RequestPasswords(watcher_passwords);
            pswd = utils::GetPassword(password_len);
        }
        selected_context_item->setData(Qt::DisplayRole, asterics);
        selected_context_item->setData(Qt::UserRole, pswd);
    } else {
        ;
    }
    selected_context_item = nullptr;
}

void Widget::seed_pass_has_been_set()
{
    main::pass_gen = watcher_seed_pass_gen.result();
    QMessageBox mb;
    if (!main::pass_gen.is_succes())
    {
        mb.warning(this, "Failure", "The key was not set: put another phrase.");
    } else {
        if (!main::storage.isEmpty()) {
            mb.information(this, "Success", "The key was set");
            ui->tableWidget->clearContents();
            while (ui->tableWidget->rowCount() > 0) {
                ui->tableWidget->removeRow(0);
            }
            load_storage();
            ui->btn_input_master_phrase->setText(QString::fromUtf8("Your storage: %1").arg(main::storage));
            ui->btn_generate->setEnabled(!main::storage.isEmpty());
            ui->btn_add_empty_row->setEnabled(!main::storage.isEmpty());
            ui->btn_generate->setFocus();
            ui->btn_generate->setText(gen_pass_txt);
        }
    }
}

void Widget::on_btn_input_master_phrase_clicked()
{
    txt_edit_master_phrase->setVisible(true);
    txt_edit_master_phrase->resize(400, 250);
    txt_edit_master_phrase->setFocus();
}

void Widget::update_master_phrase()
{
    QString text {txt_edit_master_phrase->toPlainText()};
    txt_edit_master_phrase->clear();
    if (text.isEmpty()) {
        return;
    }
    ui->btn_input_master_phrase->setEnabled(false);
    lfsr_hash::u128 hash = utils::gen_hash_for_pass_gen(text, std::random_device{}());
    utils::fill_key_by_hash128(hash);
    // Clear
    #pragma optimize( "", off )
        hash.first = 0; hash.second = 0;
    #pragma optimize( "", on )
    {
        lfsr_hash::u128 hash_fs = utils::gen_hash_for_storage(text);
        main::storage = utils::GetStorageName(hash_fs);
        lfsr_hash::u128 hash_enc = utils::gen_hash_for_encryption(text);
        lfsr_rng::STATE st1 = utils::fill_state_by_hash(hash_enc);
        watcher_seed_enc_gen.setFuture(main::worker.seed(st1));
        watcher_seed_dec_gen.setFuture(main::worker.seed(st1));
        lfsr_hash::u128 hash_enc_inner = utils::gen_hash_for_inner_encryption(text);
        lfsr_rng::STATE st2 = utils::fill_state_by_hash(hash_enc_inner);
        watcher_seed_enc_inner_gen.setFuture(main::worker.seed(st2));
        watcher_seed_dec_inner_gen.setFuture(main::worker.seed(st2));
        // Clear
        #pragma optimize( "", off )
            hash_fs = {0, 0};
            hash_enc = {0, 0};
            hash_enc_inner = {0, 0};
            for (auto& el : text) {
                el = '\0';
            }
        #pragma optimize( "", on )
        utils::clear_lfsr_rng_state(st1);
        utils::clear_lfsr_rng_state(st2);
        watcher_seed_enc_gen.waitForFinished();
        watcher_seed_dec_gen.waitForFinished();
        watcher_seed_enc_inner_gen.waitForFinished();
        watcher_seed_dec_inner_gen.waitForFinished();
        enc::gamma_gen = watcher_seed_enc_gen.result();
        dec::gamma_gen = watcher_seed_dec_gen.result();
        enc_inner::gamma_gen = watcher_seed_enc_inner_gen.result();
        dec_inner::gamma_gen = watcher_seed_dec_inner_gen.result();
    }
    emit master_phrase_ready();
}

void Widget::set_master_key()
{
    lfsr_rng::STATE st; // key => state => generator
    for (int i=0; i<main::key.N(); ++i) {
        st[i] = main::key.get_key(i);
    }
    watcher_seed_pass_gen.setFuture( main::worker.seed(st) );
    utils::clear_main_key();
    utils::clear_lfsr_rng_state(st);
}

void Widget::on_btn_generate_clicked()
{
    if (!watcher_seed_pass_gen.isFinished()) {
        qDebug() << "Rejected: PRNG is not initialized yet!";
        return;
    }
    if (num_of_passwords < 1) {
        qDebug() << "Rejected: not correct password length!";
        return;
    }
    if (!main::pass_gen.is_succes()) {
        qDebug() << "Rejected: set the master phrase first!";
        return;
    }
    ui->btn_generate->setText(QString::fromUtf8("Wait..."));
    ui->btn_generate->setEnabled(false);
    QString pswd = utils::GetPassword(password_len);
    if (pswd.length() < password_len) {
        RequestPasswords(watcher_passwords);
        pswd = utils::GetPassword(password_len);
    }
    ui->tableWidget->insertRow(ui->tableWidget->rowCount());
    const int row = ui->tableWidget->rowCount() - 1;
    QTableWidgetItem* item = new QTableWidgetItem();
    item->setData(Qt::DisplayRole, asterics);
    item->setData(Qt::UserRole, pswd);
    ui->tableWidget->setItem(row, pswd_column_idx, item);
    ui->tableWidget->resizeColumnToContents(pswd_column_idx);
    ui->btn_generate->setText(gen_pass_txt);
    ui->btn_generate->setEnabled(true);
    ui->btn_generate->setFocus();
}

void Widget::on_spbx_pass_len_valueChanged(int arg1)
{
    password_len = arg1 - (arg1 % 5);
}

void Widget::on_spbx_pass_len_editingFinished()
{
    if (ui->spbx_pass_len->value() != password_len)
        ui->spbx_pass_len->setValue(password_len);
}

void Widget::tableWidget_customContextMenuRequested(const QPoint &pos)
{
    selected_context_item = ui->tableWidget->itemAt(pos);
    if (!selected_context_item) {
        QMenu menu;
        menu.addAction(removeAct);
        menu.exec(ui->tableWidget->mapToGlobal(pos));
        return;
    }
    QMenu menu;
    menu.addAction(copyAct);
    menu.addAction(removeAct);
    if (selected_context_item->column() == pswd_column_idx) {
        menu.addAction(updatePassAct);
    }
    menu.exec(ui->tableWidget->mapToGlobal(pos));
}

void Widget::on_btn_add_empty_row_clicked()
{
    ui->tableWidget->insertRow(ui->tableWidget->rowCount());
    ui->tableWidget->setItem(ui->tableWidget->rowCount()-1, pswd_column_idx, new QTableWidgetItem(""));
}

void Widget::save_to_store()
{
    if (main::storage.isEmpty()) {
        qDebug() << "Empty storage.";
        return;
    }
    if (!enc::gamma_gen.is_succes()) {
        qDebug() << "Empty encryption.";
        return;
    }
    if (!enc_inner::gamma_gen.is_succes()) {
        qDebug() << "Empty inner encryption.";
        return;
    }
    if (ui->tableWidget->rowCount() < 1) {
        qDebug() << "Empty table.";
        return;
    }
    QFile file(main::storage);
    if (file.open(QFile::WriteOnly))
    {
        QStringList strList;
        QByteArray out;
        QByteArray encoded_string;
        utils::init_encryption();
        const int rc = ui->tableWidget->rowCount();
        const int cc = ui->tableWidget->columnCount();
        for( int row = 0; row < rc; ++row )
        {
            strList.clear();
            for( int col = 0; col < cc; ++col )
            {
                if (ui->tableWidget->item(row, col)) {
                    if (col != pswd_column_idx) {
                        const auto& txt = ui->tableWidget->item(row, col)->text();
                        strList << (txt == "" ? symbols::empty_item : txt);
                    } else {
                        strList << ui->tableWidget->item(row, col)->data(Qt::UserRole).toString();
                    }
                }
                else {
                    strList << symbols::empty_item;
                }
            }
            auto fromUtf16 = QStringEncoder(QStringEncoder::Utf8);
            QString tmp = strList.join( symbols::row_delimiter );
            tmp.append( (row < ui->tableWidget->rowCount() - 1 ? symbols::col_delimiter : symbols::end_message) );
            encoded_string.append(fromUtf16( tmp ));
        }
        utils::padd_256(encoded_string);
        QByteArray encrypted_inner;
        utils::encrypt256_inner(encoded_string, encrypted_inner);
        QByteArray permuted;
        utils::encode_dlog256(encrypted_inner, permuted);
        utils::encrypt(permuted, out);
        utils::finalize_encryption();
        utils::encode_crc(out);
        out.append(VERSION);
        utils::insert_hash128_256padd(out);
        file.write(out);
        file.close();
        qDebug() << "Table has been saved!";
    } else {
        ;
    }
}

void Widget::load_storage()
{
    if (main::storage.isEmpty()) {
        qDebug() << "Empty storage.";
        return;
    }
    if (!dec::gamma_gen.is_succes()) {
        qDebug() << "Empty decryption.";
        return;
    }
    if (!dec_inner::gamma_gen.is_succes()) {
        qDebug() << "Empty inner decryption.";
        return;
    }
    if (ui->tableWidget->rowCount() > 0) {
        qDebug() << "Table is not empty.";
        return;
    }
    QFile file(main::storage);
    QStringList rowOfData;
    QStringList rowData;
    QByteArray data;
    if (file.open(QFile::ReadOnly))
    {
        data = file.readAll();
        const bool hash_check_is_ok = utils::extract_and_check_hash128_256padd(data);
        if (!hash_check_is_ok) {
            QMessageBox mb;
            mb.critical(nullptr, QString::fromUtf8("LFSR hash128: storage data failure"),
                        QString::fromUtf8("See the file: %1").arg(main::storage));
            main::storage = "";
            return;
        }
        QString version;
        while (!data.isEmpty() && data.back() != '#') {
            version.push_back(data.back());
            data.removeLast();
        }
        if (!data.isEmpty()) {
            data.removeLast();
        }
        std::reverse(version.begin(), version.end());
        const QString etalon_version = QString(VERSION).remove("#");
        if (version != etalon_version) {
            qDebug() << "Unrecognized version: " << version;
            return;
        }
        if (!utils::decode_crc(data)) {
            qDebug() << "CRC: storage data failure: " << main::storage;
            QMessageBox mb;
            mb.critical(nullptr, QString::fromUtf8("CRC: storage data failure"),
                        QString::fromUtf8("See the file: %1").arg(main::storage));
            main::storage = "";
            return;
        }
        utils::init_decryption();
        QByteArray decrypted;
        utils::decrypt(data, decrypted);
        QByteArray depermuted;
        utils::decode_dlog256(decrypted, depermuted);
        QByteArray decrypted_inner;
        utils::decrypt256_inner(depermuted, decrypted_inner);
        utils::dpadd_256(decrypted_inner);
        auto toUtf16 = QStringDecoder(QStringDecoder::Utf8);
        QString decoded_string = toUtf16(decrypted_inner);
        if (decoded_string.isEmpty()) {
            qDebug() << "Unrecognized error while loading.";
            return;
        }
        decoded_string.removeLast(); // 0x0003 = symbols::end_message.
        rowOfData = decoded_string.split(symbols::col_delimiter);
        utils::finalize_decryption();
        file.close();
    } else {
        // qDebug() << "Storage cannot be opened.";
        return;
    }
    if (rowOfData.isEmpty()) {
        qDebug() << "Empty row data.";
        return;
    }
    for (int row = 0; row < rowOfData.size(); row++)
    {
        rowData = rowOfData.at(row).split(symbols::row_delimiter);
        if (rowData.size() == ui->tableWidget->columnCount()) {
            ui->tableWidget->insertRow(row);
        } else {
            qDebug() << "Unrecognized column size: " << ui->tableWidget->columnCount() << " vs " << rowData.size();
            break;
        }
        for (int col = 0; col < rowData.size(); col++)
        {
            const QString& row_str = rowData.at(col);
            QTableWidgetItem *item = new QTableWidgetItem();
            if (col == pswd_column_idx) {
                item->setData(Qt::DisplayRole, asterics);
                item->setData(Qt::UserRole, row_str.at(0) == symbols::empty_item ? "" : row_str);
            } else {
                item->setText(row_str.at(0) == symbols::empty_item ? "" : row_str);
            }
            ui->tableWidget->setItem(row, col, item);
        }
    }
    ui->tableWidget->resizeColumnToContents(pswd_column_idx);
    qDebug() << "Table has been loaded!";
}
