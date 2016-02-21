<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "equipment".
 *
 * @property integer $serial_id
 * @property string $title
 * @property string $description
 * @property string $status
 *
 * @property StudentEquipment $studentEquipment
 */
class Equipment extends \yii\db\ActiveRecord
{
    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return 'equipment';
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            [['title', 'status'], 'required'],
            [['description'], 'string'],
            [['title'], 'string', 'max' => 29],
            [['status'], 'string', 'max' => 11]
        ];
    }

    /**
     * @inheritdoc
     */
    public function attributeLabels()
    {
        return [
            'serial_id' => 'Serial ID',
            'title' => 'Title',
            'description' => 'Description',
            'status' => 'Status',
        ];
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getStudentEquipment()
    {
        return $this->hasOne(StudentEquipment::className(), ['serial_id' => 'serial_id']);
    }
}
