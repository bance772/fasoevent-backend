<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class TestController extends Controller
{
 public function echoUrl($text)
    {
        return response()->json([
            'message' => 'Texte reçu via URL : ' . $text,
            'status' => 'success'
        ]);
    }
    }
