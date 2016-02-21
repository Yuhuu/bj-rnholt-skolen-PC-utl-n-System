<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "student_equipment".
 *
 * @property integer $id
 * @property integer $student_id
 * @property integer $serial_id
 * @property integer $borrow_status_id
 * @property integer $require_by_teacher_id
 * @property integer $start_at
 * @property integer $end_at
 *
 * @property Equipment $serial
 * @property Student $student
 */
class StudentEquipment extends \yii\db\ActiveRecord
{
    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return 'student_equipment';
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            [['student_id', 'serial_id', 'borrow_status_id', 'require_by_teacher_id', 'start_at', 'end_at'], 'required'],
            [['student_id', 'serial_id', 'borrow_status_id', 'require_by_teacher_id', 'start_at', 'end_at'], 'integer'],
            [['serial_id'], 'unique'],
            [['student_id'], 'unique']
        ];
    }

    /**
     * @inheritdoc
     */
    public function attributeLabels()
    {
        return [
            'id' => 'ID',
            'student_id' => 'Student ID',
            'serial_id' => 'Serial ID',
            'borrow_status_id' => 'Borrow Status ID',
            'require_by_teacher_id' => 'Require By Teacher ID',
            'start_at' => 'Start At',
            'end_at' => 'End At',
        ];
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getSerial()
    {
        return $this->hasOne(Equipment::className(), ['serial_id' => 'serial_id']);
    }

    /**
     * @return \yii\db\ActiveQuery
     */
    public function getStudent()
    {
        return $this->hasOne(Student::className(), ['id' => 'student_id']);
    }
}
