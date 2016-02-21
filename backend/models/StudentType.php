<?php

namespace backend\models;

use Yii;
use common\models\Student;

/**
 * This is the model class for table "student_type".
 *
 * @property integer $id
 * @property string $student_type_name
 * @property integer $student_type_value
 */
class StudentType extends \yii\db\ActiveRecord
{
    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return 'student_type';
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            [['student_type_name', 'student_type_value'], 'required'],
            [['student_type_value'], 'integer'],
            [['student_type_name'], 'string', 'max' => 30]
        ];
    }

    /**
     * @inheritdoc
     */
    public function attributeLabels()
    {
        return [
            'id' => 'ID',
            'student_type_name' => 'Student Type Name',
            'student_type_value' => 'Student Type Value',
        ];
    }
    
    public function getUsers()
    {
    return $this->hasMany(User::className(), ['user_type_id' => 'student_type_value']);
    }
}
