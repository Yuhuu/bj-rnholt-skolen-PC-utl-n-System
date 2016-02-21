<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "borrow_status".
 *
 * @property integer $id
 * @property string $borrow_status_name
 * @property integer $borrow_status_value
 */
class BorrowStatus extends \yii\db\ActiveRecord
{
    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return 'borrow_status';
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            [['borrow_status_name', 'borrow_status_value'], 'required'],
            [['borrow_status_value'], 'integer'],
            [['borrow_status_name'], 'string', 'max' => 30]
        ];
    }

    /**
     * @inheritdoc
     */
    public function attributeLabels()
    {
        return [
            'id' => 'ID',
            'borrow_status_name' => 'Borrow Status Name',
            'borrow_status_value' => 'Borrow Status Value',
        ];
    }
}
